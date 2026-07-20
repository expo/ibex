/**
 * Validate the LLP 0010 runtime manifest's REPL/keybinding sections and
 * generate the only Rust tables used by dispatch, help, completion, `.load`
 * grammar selection, source-ordinal routing, and editor control dispatch.
 *
 * @ref LLP 0010#surface-manifest — REPL and keybinding data live beside the
 * recursive Clap inventory in one runtime-owned authority.
 * @ref LLP 0022#8-commands — command recognition, aliases, modes, arity,
 * streams, affordance classification, and help are one generated contract.
 * @ref LLP 0024#2-source-identity-and-reserved-schemes — only `.load` and
 * `.time` submit sources and therefore advance the session source ordinal.
 * @ref LLP 0025#5-terminal-presentation-and-restoration — published editor
 * controls, including byte-level Ctrl+C and Ctrl+Z, come from a manifest.
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
export const runtimeSurfacePath = path.join(repoRoot, "runtime-surface.json");
export const replSurfaceSchemaPath = path.join(
  repoRoot,
  "session",
  "schema",
  "repl-surface.schema.json",
);
export const capabilityDefinitionsPath = path.join(
  repoRoot,
  "capsec",
  "registry",
  "capability-definitions.json",
);
export const policyRulesPath = path.join(
  repoRoot,
  "capsec",
  "registry",
  "policy-rules.json",
);
export const generatorPath = __filename;
export const generatedReplSurfacePaths = Object.freeze({
  rust: path.join(repoRoot, "vendored-generated", "repl_surface.generated.rs"),
  help: path.join(repoRoot, "vendored-generated", "repl_help.generated.txt"),
  table: path.join(repoRoot, "vendored-generated", "repl_surface.generated.md"),
  manifest: path.join(
    repoRoot,
    "vendored-generated",
    "repl_surface_manifest.generated.json",
  ),
});

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function relative(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function assertUnique(values, label) {
  if (values.length !== new Set(values).size) {
    throw new Error(`${label} contains a duplicate`);
  }
}

function relationKey(relation) {
  return `${relation.kind}:${relation.id}`;
}

function registryRelationIndex(capabilityDefinitionsSource, policyRulesSource) {
  const capabilityDefinitions = JSON.parse(capabilityDefinitionsSource);
  const policyRules = JSON.parse(policyRulesSource);
  const capabilities = new Set(
    capabilityDefinitions.definitions?.map((definition) => definition.id),
  );
  const rationales = new Set(
    policyRules.classifierRules?.nonCapabilityRationales?.map(
      (rationale) => rationale.id,
    ),
  );
  if (capabilities.size === 0 || rationales.size === 0) {
    throw new Error("CapSec registry relation sources are malformed");
  }
  return { capabilities, rationales };
}

function validateSemanticSurface(
  surface,
  relationIndex = registryRelationIndex(
    fs.readFileSync(capabilityDefinitionsPath, "utf8"),
    fs.readFileSync(policyRulesPath, "utf8"),
  ),
) {
  const { replSurface, keybindingSurface } = surface;
  const commandIds = replSurface.commands.map((command) => command.id);
  const canonicalNames = replSurface.commands.map((command) => command.name);
  const allNames = replSurface.commands.flatMap((command) => [
    command.name,
    ...command.aliases,
  ]);
  assertUnique(commandIds, "replSurface.commands ids");
  assertUnique(canonicalNames, "replSurface.commands canonical names");
  assertUnique(allNames, "replSurface command and alias namespace");

  const commandPattern = /^\.[A-Za-z][A-Za-z0-9_-]*$/;
  for (const command of replSurface.commands) {
    if (
      ![command.name, ...command.aliases].every((name) =>
        commandPattern.test(name),
      )
    ) {
      throw new Error(
        `${command.id}: command token violates recognition grammar`,
      );
    }
    if (!command.usage.startsWith(command.name)) {
      throw new Error(
        `${command.id}: usage must begin with its canonical name`,
      );
    }
    if (command.argument.kind === "none" && command.usage !== command.name) {
      throw new Error(`${command.id}: argument-free usage must equal its name`);
    }
    if (
      command.argument.kind === "required-remainder" &&
      !command.usage.includes(`<${command.argument.name}>`)
    ) {
      throw new Error(`${command.id}: usage omits its required argument name`);
    }
    assertUnique(
      command.registryRelations.map(relationKey),
      `${command.id}.registryRelations`,
    );
    for (const relation of command.registryRelations) {
      const known =
        relation.kind === "capability"
          ? relationIndex.capabilities.has(relation.id)
          : relationIndex.rationales.has(relation.id);
      if (!known) {
        throw new Error(
          `${command.id}: registry relation does not exist: ${relationKey(relation)}`,
        );
      }
    }
    for (const mode of command.modes) {
      if (!replSurface.modes.includes(mode)) {
        throw new Error(`${command.id}: command names undeclared mode ${mode}`);
      }
    }
  }

  if (allNames.includes(".env")) {
    throw new Error(".env is forbidden by LLP 0022 affordance parity");
  }
  const sourceSubmitting = replSurface.commands
    .filter((command) => command.sourceSubmission !== "none")
    .map((command) => command.id);
  if (sourceSubmitting.join(",") !== "load,time") {
    throw new Error("only .load and .time may submit a command-owned source");
  }
  const continuationCommands = replSurface.commands
    .filter((command) => command.states.includes("continuation"))
    .map((command) => command.id);
  if (continuationCommands.join(",") !== "break") {
    throw new Error(
      ".break must be the only command recognized in continuation state",
    );
  }

  const loadRows = replSurface.loadExtensions.rows;
  assertUnique(
    loadRows.map((row) => row.extension),
    "replSurface.loadExtensions.rows",
  );
  const typesOnly = loadRows.find((row) => row.extension === ".d.ts");
  if (typesOnly?.disposition !== "refuse-types-only") {
    throw new Error(
      ".d.ts must be matched before .ts and refused as types-only",
    );
  }
  for (const row of loadRows) {
    if (row.disposition === "script" && row.errorCode !== undefined) {
      throw new Error(
        `${row.extension}: a script row cannot carry a refusal code`,
      );
    }
    if (row.disposition.startsWith("refuse-") && row.dialect !== undefined) {
      throw new Error(
        `${row.extension}: a refusal row cannot select a dialect`,
      );
    }
  }

  const bindings = keybindingSurface.bindings;
  assertUnique(
    bindings.map((binding) => binding.id),
    "keybinding ids",
  );
  assertUnique(
    bindings.map((binding) => binding.display),
    "keybinding displays",
  );
  assertUnique(
    bindings.map((binding) => binding.bytes.join(",")),
    "keybinding byte sequences",
  );
  const interrupt = bindings.find((binding) => binding.id === "interrupt");
  if (
    interrupt?.bytes.join(",") !== "3" ||
    interrupt.action !== "interrupt-machine" ||
    interrupt.countsAsEditorInput
  ) {
    throw new Error(
      "Ctrl+C must dispatch byte 3 without counting as editor input",
    );
  }
  for (const [id, byte] of [
    ["eof", 4],
    ["reverse-history", 18],
    ["suspend", 26],
  ]) {
    const binding = bindings.find((candidate) => candidate.id === id);
    if (
      binding?.bytes.join(",") !== String(byte) ||
      !binding.countsAsEditorInput
    ) {
      throw new Error(
        `${id} must carry its pinned control byte as editor input`,
      );
    }
  }
}

export function loadReplSurface(
  filePath = runtimeSurfacePath,
  { requireCanonical = true } = {},
) {
  const source = fs.readFileSync(filePath, "utf8");
  const manifest = JSON.parse(source);
  if (requireCanonical && source !== canonicalJson(manifest)) {
    throw new Error(`${relative(filePath)} is not canonical two-space JSON`);
  }
  if (manifest.version !== 5) {
    throw new Error(`${relative(filePath)} must use runtime surface version 5`);
  }
  const surface = {
    replSurface: manifest.replSurface,
    keybindingSurface: manifest.keybindingSurface,
  };
  const schemaSource = fs.readFileSync(replSurfaceSchemaPath, "utf8");
  const capabilityDefinitionsSource = fs.readFileSync(
    capabilityDefinitionsPath,
    "utf8",
  );
  const policyRulesSource = fs.readFileSync(policyRulesPath, "utf8");
  const schema = JSON.parse(schemaSource);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  if (!validate(surface)) {
    throw new Error(
      `REPL surface schema validation failed:\n${JSON.stringify(validate.errors, null, 2)}`,
    );
  }
  validateSemanticSurface(
    surface,
    registryRelationIndex(capabilityDefinitionsSource, policyRulesSource),
  );
  return {
    manifest,
    surface,
    source,
    schemaSource,
    capabilityDefinitionsSource,
    policyRulesSource,
  };
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

function pascalCase(value) {
  return value
    .split("-")
    .map((part) => `${part[0].toUpperCase()}${part.slice(1)}`)
    .join("");
}

function enumVariant(value) {
  const variants = {
    interactive: "Interactive",
    "plain-transcript": "PlainTranscript",
    fresh: "Fresh",
    continuation: "Continuation",
    stdout: "Stdout",
    none: "None",
    "editor-control-or-none": "EditorControlOrNone",
    "presentation-only": "PresentationOnly",
    "cooperative-lifecycle": "CooperativeLifecycle",
    "terminal-operator-state": "TerminalOperatorState",
    "typed-session-effect": "TypedSessionEffect",
    "evaluation-wrapper": "EvaluationWrapper",
    "session-control": "SessionControl",
    "logical-namespace-introspection": "LogicalNamespaceIntrospection",
    capability: "Capability",
    "non-capability-rationale": "NonCapabilityRationale",
    "advance-on-source-request": "AdvanceOnSourceRequest",
    script: "Script",
    "json-data": "JsonData",
    "refuse-module-kind": "RefuseModuleKind",
    "refuse-types-only": "RefuseTypesOnly",
    "refuse-unknown-or-extensionless": "RefuseUnknownOrExtensionless",
    javascript: "JavaScript",
    "javascript-jsx": "JavaScriptJsx",
    typescript: "TypeScript",
    "typescript-jsx": "TypeScriptJsx",
    json: "Json",
    "bounded-asynchronous-completion": "BoundedAsynchronousCompletion",
    "interrupt-machine": "InterruptMachine",
    "orderly-eof-or-delete-forward": "OrderlyEofOrDeleteForward",
    "reverse-history-search": "ReverseHistorySearch",
    "suspend-transaction": "SuspendTransaction",
  };
  const variant = variants[value];
  if (!variant) throw new Error(`no Rust enum variant for ${value}`);
  return variant;
}

function rustEnumSlice(type, values) {
  return `&[${values.map((value) => `${type}::${enumVariant(value)}`).join(", ")}]`;
}

function renderHelp(surface) {
  const commandLabels = surface.replSurface.commands.map((command) => {
    const aliases =
      command.aliases.length > 0 ? ` (${command.aliases.join(", ")})` : "";
    return `${command.usage}${aliases}`;
  });
  const commandWidth = Math.max(...commandLabels.map((label) => label.length));
  const bindingWidth = Math.max(
    ...surface.keybindingSurface.bindings.map(
      (binding) => binding.display.length,
    ),
  );
  const lines = ["REPL Commands:"];
  for (const [index, command] of surface.replSurface.commands.entries()) {
    lines.push(
      `  ${commandLabels[index].padEnd(commandWidth)}  ${command.help}`,
    );
  }
  lines.push("", "Keybindings:");
  for (const binding of surface.keybindingSurface.bindings) {
    lines.push(`  ${binding.display.padEnd(bindingWidth)}  ${binding.help}`);
  }
  return `${lines.join("\n")}\n`;
}

function renderRust(surface, helpText, binding) {
  const { replSurface, keybindingSurface } = surface;
  const lines = [
    "// @generated by packages/ibex-devtools/src/scripts/generate-repl-surface.mjs",
    "// Source: runtime-surface.json#replSurface,#keybindingSurface",
    `// Source SHA-256: ${binding.sourceDigest}`,
    "// Schema: session/schema/repl-surface.schema.json",
    `// Schema SHA-256: ${binding.schemaDigest}`,
    `// Generator SHA-256: ${binding.generatorDigest}`,
    "// Do not edit by hand.",
    "// @ref LLP 0022#8-commands — generated command, help, and completion authority",
    "// @ref LLP 0025#5-terminal-presentation-and-restoration — generated key controls",
    "",
    "#![allow(dead_code)]",
    "",
    "#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]",
    "pub enum ReplCommandId {",
    ...replSurface.commands.map((command) => `    ${pascalCase(command.id)},`),
    "}",
    "",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum ArgumentKind {",
    "    None,",
    "    RequiredRemainder,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum ReplMode {",
    "    Interactive,",
    "    PlainTranscript,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum ReplState {",
    "    Fresh,",
    "    Continuation,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum SuccessOutput {",
    "    Stdout,",
    "    None,",
    "    EditorControlOrNone,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum Affordance {",
    "    PresentationOnly,",
    "    CooperativeLifecycle,",
    "    TerminalOperatorState,",
    "    TypedSessionEffect,",
    "    EvaluationWrapper,",
    "    SessionControl,",
    "    LogicalNamespaceIntrospection,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum RegistryRelationKind {",
    "    Capability,",
    "    NonCapabilityRationale,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum SourceSubmission {",
    "    None,",
    "    AdvanceOnSourceRequest,",
    "}",
    "",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub struct RegistryRelation {",
    "    pub kind: RegistryRelationKind,",
    "    pub id: &'static str,",
    "}",
    "",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub struct ReplCommandSpec {",
    "    pub id: ReplCommandId,",
    "    pub name: &'static str,",
    "    pub aliases: &'static [&'static str],",
    "    pub usage: &'static str,",
    "    pub argument_kind: ArgumentKind,",
    "    pub argument_name: Option<&'static str>,",
    "    pub modes: &'static [ReplMode],",
    "    pub states: &'static [ReplState],",
    "    pub success_output: SuccessOutput,",
    "    pub affordance: Affordance,",
    "    pub registry_relations: &'static [RegistryRelation],",
    "    pub source_submission: SourceSubmission,",
    "    pub help: &'static str,",
    "}",
    "",
    "pub const RUNTIME_SURFACE_SOURCE_SHA256: &str =",
    `    ${rustString(binding.sourceDigest)};`,
    "pub const REPL_SURFACE_SCHEMA_SHA256: &str =",
    `    ${rustString(binding.schemaDigest)};`,
    "pub const REPL_SURFACE_GENERATOR_SHA256: &str =",
    `    ${rustString(binding.generatorDigest)};`,
    "pub const CAPABILITY_DEFINITIONS_SHA256: &str =",
    `    ${rustString(binding.capabilityDefinitionsDigest)};`,
    "pub const POLICY_RULES_SHA256: &str =",
    `    ${rustString(binding.policyRulesDigest)};`,
    `pub const REPL_SURFACE_VERSION: u32 = ${replSurface.version};`,
    `pub const KEYBINDING_SURFACE_VERSION: u32 = ${keybindingSurface.version};`,
    `pub const REPL_HELP_TEXT: &str = ${rustString(helpText)};`,
    "",
    "pub static REPL_COMMANDS: &[ReplCommandSpec] = &[",
  ];
  for (const command of replSurface.commands) {
    const relationRows =
      command.registryRelations.length === 0
        ? ["        registry_relations: &[],"]
        : command.registryRelations.length === 1
          ? [
              "        registry_relations: &[RegistryRelation {",
              `            kind: RegistryRelationKind::${enumVariant(command.registryRelations[0].kind)},`,
              `            id: ${rustString(command.registryRelations[0].id)},`,
              "        }],",
            ]
          : [
            "        registry_relations: &[",
            ...command.registryRelations.flatMap((relation) => [
              "            RegistryRelation {",
              `                kind: RegistryRelationKind::${enumVariant(relation.kind)},`,
              `                id: ${rustString(relation.id)},`,
              "            },",
            ]),
            "        ],",
          ];
    lines.push(
      "    ReplCommandSpec {",
      `        id: ReplCommandId::${pascalCase(command.id)},`,
      `        name: ${rustString(command.name)},`,
      `        aliases: &[${command.aliases.map(rustString).join(", ")}],`,
      `        usage: ${rustString(command.usage)},`,
      `        argument_kind: ArgumentKind::${command.argument.kind === "none" ? "None" : "RequiredRemainder"},`,
      `        argument_name: ${command.argument.name ? `Some(${rustString(command.argument.name)})` : "None"},`,
      `        modes: ${rustEnumSlice("ReplMode", command.modes)},`,
      `        states: ${rustEnumSlice("ReplState", command.states)},`,
      `        success_output: SuccessOutput::${enumVariant(command.successOutput)},`,
      `        affordance: Affordance::${enumVariant(command.affordance)},`,
      ...relationRows,
      `        source_submission: SourceSubmission::${enumVariant(command.sourceSubmission)},`,
      `        help: ${rustString(command.help)},`,
      "    },",
    );
  }
  lines.push(
    "];",
    "",
    "pub fn command_by_name(name: &str) -> Option<&'static ReplCommandSpec> {",
    "    REPL_COMMANDS",
    "        .iter()",
    "        .find(|command| command.name == name || command.aliases.contains(&name))",
    "}",
    "",
    "pub static COMMAND_COMPLETIONS: &[&str] = &[",
    `    ${replSurface.commands
      .flatMap((command) => [command.name, ...command.aliases])
      .map(rustString)
      .join(", ")},`,
    "];",
    "",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum CommandLine<'a> {",
    "    JavaScript,",
    "    Known {",
    "        command: &'static ReplCommandSpec,",
    "        argument: &'a str,",
    "    },",
    "    Unknown {",
    "        name: &'a str,",
    "    },",
    "}",
    "",
    "pub fn classify_command_line(line: &str) -> CommandLine<'_> {",
    "    let Some((start, first)) = line.char_indices().find(|(_, ch)| !ch.is_whitespace()) else {",
    "        return CommandLine::JavaScript;",
    "    };",
    "    if first != '.' {",
    "        return CommandLine::JavaScript;",
    "    }",
    "    let name_start = start + first.len_utf8();",
    "    let Some((_, first_name)) = line[name_start..].char_indices().next() else {",
    "        return CommandLine::JavaScript;",
    "    };",
    "    if !first_name.is_ascii_alphabetic() {",
    "        return CommandLine::JavaScript;",
    "    }",
    "    let scan_start = name_start + first_name.len_utf8();",
    "    let mut name_end = scan_start;",
    "    for (offset, ch) in line[scan_start..].char_indices() {",
    "        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {",
    "            name_end = scan_start + offset + ch.len_utf8();",
    "            continue;",
    "        }",
    "        if !ch.is_whitespace() {",
    "            return CommandLine::JavaScript;",
    "        }",
    "        break;",
    "    }",
    "    let name = &line[start..name_end];",
    "    let argument = line[name_end..].trim_start_matches(char::is_whitespace);",
    "    match command_by_name(name) {",
    "        Some(command) => CommandLine::Known { command, argument },",
    "        None => CommandLine::Unknown { name },",
    "    }",
    "}",
    "",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum ArgumentError {",
    "    Missing,",
    "    Unexpected,",
    "}",
    "",
    "pub fn validate_argument(command: &ReplCommandSpec, argument: &str) -> Result<(), ArgumentError> {",
    "    match (command.argument_kind, argument.is_empty()) {",
    "        (ArgumentKind::None, false) => Err(ArgumentError::Unexpected),",
    "        (ArgumentKind::RequiredRemainder, true) => Err(ArgumentError::Missing),",
    "        _ => Ok(()),",
    "    }",
    "}",
    "",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum ParserDialect {",
    "    JavaScript,",
    "    JavaScriptJsx,",
    "    TypeScript,",
    "    TypeScriptJsx,",
    "    Json,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum LoadDisposition {",
    "    Script(ParserDialect),",
    "    JsonData,",
    "    RefuseModuleKind,",
    "    RefuseTypesOnly,",
    "    RefuseUnknownOrExtensionless,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub struct LoadExtensionSpec {",
    "    pub extension: &'static str,",
    "    pub disposition: LoadDisposition,",
    "    pub error_code: Option<&'static str>,",
    "}",
    "pub static LOAD_EXTENSIONS: &[LoadExtensionSpec] = &[",
  );
  const sortedLoadRows = [...replSurface.loadExtensions.rows].sort(
    (left, right) => right.extension.length - left.extension.length,
  );
  for (const row of sortedLoadRows) {
    let disposition;
    if (row.disposition === "script") {
      disposition = `LoadDisposition::Script(ParserDialect::${enumVariant(row.dialect)})`;
    } else if (row.disposition === "json-data") {
      disposition = "LoadDisposition::JsonData";
    } else {
      disposition = `LoadDisposition::${enumVariant(row.disposition)}`;
    }
    lines.push(
      "    LoadExtensionSpec {",
      `        extension: ${rustString(row.extension)},`,
      `        disposition: ${disposition},`,
      `        error_code: ${row.errorCode ? `Some(${rustString(row.errorCode)})` : "None"},`,
      "    },",
    );
  }
  lines.push(
    "];",
    `pub const LOAD_DEFAULT_ERROR_CODE: &str = ${rustString(replSurface.loadExtensions.defaultErrorCode)};`,
    "pub fn classify_load_path(path: &str) -> LoadDisposition {",
    "    LOAD_EXTENSIONS",
    "        .iter()",
    "        .find(|row| path.ends_with(row.extension))",
    "        .map(|row| row.disposition)",
    "        .unwrap_or(LoadDisposition::RefuseUnknownOrExtensionless)",
    "}",
    "",
    "#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]",
    "pub enum KeybindingId {",
    ...keybindingSurface.bindings.map(
      (binding) => `    ${pascalCase(binding.id)},`,
    ),
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub enum KeybindingAction {",
    "    BoundedAsynchronousCompletion,",
    "    InterruptMachine,",
    "    OrderlyEofOrDeleteForward,",
    "    ReverseHistorySearch,",
    "    SuspendTransaction,",
    "}",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    "pub struct KeybindingSpec {",
    "    pub id: KeybindingId,",
    "    pub display: &'static str,",
    "    pub bytes: &'static [u8],",
    "    pub action: KeybindingAction,",
    "    pub counts_as_editor_input: bool,",
    "    pub help: &'static str,",
    "}",
    "pub static KEYBINDINGS: &[KeybindingSpec] = &[",
  );
  for (const bindingRow of keybindingSurface.bindings) {
    lines.push(
      "    KeybindingSpec {",
      `        id: KeybindingId::${pascalCase(bindingRow.id)},`,
      `        display: ${rustString(bindingRow.display)},`,
      `        bytes: &[${bindingRow.bytes.join(", ")}],`,
      `        action: KeybindingAction::${enumVariant(bindingRow.action)},`,
      `        counts_as_editor_input: ${bindingRow.countsAsEditorInput},`,
      `        help: ${rustString(bindingRow.help)},`,
      "    },",
    );
  }
  lines.push(
    "];",
    "pub fn keybinding_for_bytes(bytes: &[u8]) -> Option<&'static KeybindingSpec> {",
    "    KEYBINDINGS.iter().find(|binding| binding.bytes == bytes)",
    "}",
    "",
  );
  return lines.join("\n");
}

function markdownCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

function renderTable(surface, binding) {
  const lines = [
    "<!-- @generated by packages/ibex-devtools/src/scripts/generate-repl-surface.mjs -->",
    `<!-- source sha256: ${binding.sourceDigest} -->`,
    "# Generated REPL surface",
    "",
    "| Command | Aliases | Argument | Modes | Output | Affordance | Source submission | Help |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const command of surface.replSurface.commands) {
    lines.push(
      `| ${markdownCell(command.name)} | ${markdownCell(command.aliases.join(", ") || "—")} | ${markdownCell(command.argument.kind)} | ${markdownCell(command.modes.join(", "))} | ${markdownCell(command.successOutput)} | ${markdownCell(command.affordance)} | ${markdownCell(command.sourceSubmission)} | ${markdownCell(command.help)} |`,
    );
  }
  lines.push(
    "",
    "| Key | Bytes | Action | Editor input | Help |",
    "| --- | --- | --- | --- | --- |",
  );
  for (const keybinding of surface.keybindingSurface.bindings) {
    lines.push(
      `| ${markdownCell(keybinding.display)} | ${markdownCell(keybinding.bytes.join(" "))} | ${markdownCell(keybinding.action)} | ${keybinding.countsAsEditorInput ? "yes" : "no"} | ${markdownCell(keybinding.help)} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

export function renderReplSurfaceArtifacts(
  surface,
  {
    source = fs.readFileSync(runtimeSurfacePath, "utf8"),
    schemaSource = fs.readFileSync(replSurfaceSchemaPath, "utf8"),
    generatorSource = fs.readFileSync(generatorPath, "utf8"),
    capabilityDefinitionsSource = fs.readFileSync(
      capabilityDefinitionsPath,
      "utf8",
    ),
    policyRulesSource = fs.readFileSync(policyRulesPath, "utf8"),
  } = {},
) {
  validateSemanticSurface(
    surface,
    registryRelationIndex(capabilityDefinitionsSource, policyRulesSource),
  );
  const binding = {
    sourceDigest: sha256(source),
    schemaDigest: sha256(schemaSource),
    generatorDigest: sha256(generatorSource),
    capabilityDefinitionsDigest: sha256(capabilityDefinitionsSource),
    policyRulesDigest: sha256(policyRulesSource),
  };
  const help = renderHelp(surface);
  const artifacts = {
    rust: renderRust(surface, help, binding),
    help,
    table: renderTable(surface, binding),
  };
  artifacts.manifest = canonicalJson({
    generated: true,
    version: 1,
    source: {
      path: relative(runtimeSurfacePath),
      sha256: binding.sourceDigest,
    },
    schema: {
      path: relative(replSurfaceSchemaPath),
      sha256: binding.schemaDigest,
    },
    generator: {
      path: relative(generatorPath),
      sha256: binding.generatorDigest,
    },
    registry: [
      {
        path: relative(capabilityDefinitionsPath),
        sha256: binding.capabilityDefinitionsDigest,
      },
      {
        path: relative(policyRulesPath),
        sha256: binding.policyRulesDigest,
      },
    ],
    outputs: Object.entries(artifacts).map(([name, content]) => ({
      name,
      path: relative(generatedReplSurfacePaths[name]),
      sha256: sha256(content),
    })),
  });
  return { ...artifacts, binding };
}

function outputEntries(rendered) {
  return Object.entries(generatedReplSurfacePaths).map(([name, filePath]) => ({
    path: filePath,
    content: rendered[name],
    label: `REPL surface ${name}`,
  }));
}

export function checkReplSurfaceArtifacts(rendered) {
  const stale = [];
  for (const [name, filePath] of Object.entries(generatedReplSurfacePaths)) {
    try {
      assertConfinedGeneratedFile(repoRoot, filePath, `REPL surface ${name}`);
    } catch {
      stale.push(relative(filePath));
      continue;
    }
    if (fs.readFileSync(filePath, "utf8") !== rendered[name]) {
      stale.push(relative(filePath));
    }
  }
  return stale;
}

export function writeReplSurfaceArtifacts(rendered) {
  writeGeneratedFilesTransactionally(repoRoot, outputEntries(rendered), () => {
    const stale = checkReplSurfaceArtifacts(rendered);
    if (stale.length > 0) {
      throw new Error(
        `generated REPL surface failed validation: ${stale.join(", ")}`,
      );
    }
  });
}

function main(argv) {
  const write = argv.includes("--write");
  const check = argv.includes("--check");
  const unknown = argv.filter(
    (argument) => !["--write", "--check"].includes(argument),
  );
  if (unknown.length > 0 || write === check) {
    throw new Error(
      "usage: bun packages/ibex-devtools/src/scripts/generate-repl-surface.mjs (--write|--check)",
    );
  }
  const {
    surface,
    source,
    schemaSource,
    capabilityDefinitionsSource,
    policyRulesSource,
  } = loadReplSurface();
  const rendered = renderReplSurfaceArtifacts(surface, {
    source,
    schemaSource,
    capabilityDefinitionsSource,
    policyRulesSource,
  });
  if (write) {
    writeReplSurfaceArtifacts(rendered);
    for (const filePath of Object.values(generatedReplSurfacePaths)) {
      console.log(`wrote ${relative(filePath)}`);
    }
    return;
  }
  const stale = checkReplSurfaceArtifacts(rendered);
  if (stale.length > 0) {
    console.error(
      `REPL surface generated artifacts are stale: ${stale.join(", ")}`,
    );
    process.exitCode = 1;
  } else {
    console.log(
      `REPL surface checked: ${surface.replSurface.commands.length} commands / ${surface.keybindingSurface.bindings.length} keybindings`,
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
