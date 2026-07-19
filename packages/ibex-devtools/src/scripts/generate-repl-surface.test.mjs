// @ref LLP 0022#8-commands — dispatcher, help, completion, arity, aliases,
// modes, output, and affordance classification share one generated table.
// @ref LLP 0024#2-source-identity-and-reserved-schemes — command-owned source
// submissions advance exactly one source ordinal.
// @ref LLP 0025#5-terminal-presentation-and-restoration — the published
// control-byte vocabulary is generated and independently executable.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  checkReplSurfaceArtifacts,
  generatedReplSurfacePaths,
  loadReplSurface,
  renderReplSurfaceArtifacts,
} from "./generate-repl-surface.mjs";

let manifest;
let surface;
let source;
let schemaSource;
let capabilityDefinitionsSource;
let policyRulesSource;
let rendered;
let temporaryDirectory;

beforeAll(() => {
  ({
    manifest,
    surface,
    source,
    schemaSource,
    capabilityDefinitionsSource,
    policyRulesSource,
  } = loadReplSurface());
  rendered = renderReplSurfaceArtifacts(surface, {
    source,
    schemaSource,
    capabilityDefinitionsSource,
    policyRulesSource,
  });
  temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "ibex-repl-surface-"),
  );
});

afterAll(() => {
  if (temporaryDirectory) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

function writeManifest(name, value, { canonical = true } = {}) {
  const filePath = path.join(temporaryDirectory, name);
  const json = JSON.stringify(value, null, canonical ? 2 : 0);
  fs.writeFileSync(filePath, canonical ? `${json}\n` : json);
  return filePath;
}

describe("LLP 0022/0025 generated REPL surface", () => {
  test("pins the exhaustive v1 command and alias namespace", () => {
    expect(surface.replSurface.commands.map((command) => command.id)).toEqual([
      "help",
      "exit",
      "clear",
      "load",
      "time",
      "break",
      "mounts",
    ]);
    expect(
      surface.replSurface.commands.flatMap((command) => [
        command.name,
        ...command.aliases,
      ]),
    ).toEqual([
      ".help",
      ".h",
      ".exit",
      ".quit",
      ".q",
      ".clear",
      ".cls",
      ".load",
      ".time",
      ".break",
      ".mounts",
    ]);
    expect(JSON.stringify(surface)).not.toContain(".env");
  });

  test("pins source submission and typed registry relations", () => {
    const commands = Object.fromEntries(
      surface.replSurface.commands.map((command) => [command.id, command]),
    );
    expect(
      surface.replSurface.commands
        .filter((command) => command.sourceSubmission !== "none")
        .map((command) => command.id),
    ).toEqual(["load", "time"]);
    expect(commands.load.registryRelations).toEqual([
      {
        kind: "non-capability-rationale",
        id: "authenticated-code-ingress",
      },
      { kind: "capability", id: "fs:list" },
      { kind: "capability", id: "fs:read" },
    ]);
    expect(commands.exit.registryRelations).toEqual([
      { kind: "capability", id: "lifecycle:exit" },
    ]);
  });

  test("pins every load dialect and named refusal edge", () => {
    expect(surface.replSurface.loadExtensions.rows).toEqual([
      {
        extension: ".d.ts",
        disposition: "refuse-types-only",
        errorCode: "load-types-only",
      },
      { extension: ".js", disposition: "script", dialect: "javascript" },
      {
        extension: ".jsx",
        disposition: "script",
        dialect: "javascript-jsx",
      },
      { extension: ".ts", disposition: "script", dialect: "typescript" },
      {
        extension: ".tsx",
        disposition: "script",
        dialect: "typescript-jsx",
      },
      { extension: ".json", disposition: "json-data", dialect: "json" },
      {
        extension: ".mjs",
        disposition: "refuse-module-kind",
        errorCode: "load-module-kind",
      },
      {
        extension: ".cjs",
        disposition: "refuse-module-kind",
        errorCode: "load-module-kind",
      },
      {
        extension: ".mts",
        disposition: "refuse-module-kind",
        errorCode: "load-module-kind",
      },
      {
        extension: ".cts",
        disposition: "refuse-module-kind",
        errorCode: "load-module-kind",
      },
    ]);
    expect(surface.replSurface.loadExtensions.defaultDisposition).toBe(
      "refuse-unknown-or-extensionless",
    );
  });

  test("pins the published byte controls and interrupt-credit classification", () => {
    expect(surface.keybindingSurface.bindings).toEqual([
      {
        id: "complete",
        display: "Tab",
        bytes: [9],
        action: "bounded-asynchronous-completion",
        countsAsEditorInput: true,
        help: "Complete without authorizing effects or evaluating user code",
      },
      {
        id: "interrupt",
        display: "Ctrl+C",
        bytes: [3],
        action: "interrupt-machine",
        countsAsEditorInput: false,
        help: "Cancel, discard, or escalate according to session state",
      },
      {
        id: "eof",
        display: "Ctrl+D",
        bytes: [4],
        action: "orderly-eof-or-delete-forward",
        countsAsEditorInput: true,
        help: "Exit at an empty prompt; otherwise delete forward",
      },
      {
        id: "reverse-history",
        display: "Ctrl+R",
        bytes: [18],
        action: "reverse-history-search",
        countsAsEditorInput: true,
        help: "Search session history in reverse",
      },
      {
        id: "suspend",
        display: "Ctrl+Z",
        bytes: [26],
        action: "suspend-transaction",
        countsAsEditorInput: true,
        help: "Restore the terminal, suspend, and recapture on resume",
      },
    ]);
  });

  test("help is generated from every command, alias, and keybinding", () => {
    expect(rendered.help).toBe(
      fs.readFileSync(generatedReplSurfacePaths.help, "utf8"),
    );
    for (const command of surface.replSurface.commands) {
      expect(rendered.help).toContain(command.usage);
      expect(rendered.help).toContain(command.help);
      for (const alias of command.aliases)
        expect(rendered.help).toContain(alias);
    }
    for (const binding of surface.keybindingSurface.bindings) {
      expect(rendered.help).toContain(binding.display);
      expect(rendered.help).toContain(binding.help);
    }
  });

  test("rejects noncanonical, schema-invalid, and semantically ambiguous inputs", () => {
    expect(() =>
      loadReplSurface(
        writeManifest("noncanonical.json", manifest, { canonical: false }),
      ),
    ).toThrow(/not canonical/);

    const extraKey = structuredClone(manifest);
    extraKey.replSurface.commands[0].unowned = true;
    expect(() =>
      loadReplSurface(writeManifest("extra-key.json", extraKey)),
    ).toThrow(/schema validation failed/i);

    const duplicateAlias = structuredClone(surface);
    duplicateAlias.replSurface.commands[1].aliases.push(".h");
    expect(() => renderReplSurfaceArtifacts(duplicateAlias)).toThrow(
      /command and alias namespace contains a duplicate/,
    );

    const environmentCommand = structuredClone(surface);
    environmentCommand.replSurface.commands[0].name = ".env";
    environmentCommand.replSurface.commands[0].usage = ".env";
    expect(() => renderReplSurfaceArtifacts(environmentCommand)).toThrow(
      /.env is forbidden/,
    );

    const unknownRegistryRelation = structuredClone(surface);
    unknownRegistryRelation.replSurface.commands[0].registryRelations.push({
      kind: "capability",
      id: "runtime:not-registered",
    });
    expect(() =>
      renderReplSurfaceArtifacts(unknownRegistryRelation),
    ).toThrow(/registry relation does not exist/);
  });

  test("renders deterministically and all checked-in artifacts are current", () => {
    expect(
      renderReplSurfaceArtifacts(surface, { source, schemaSource }),
    ).toEqual(rendered);
    expect(checkReplSurfaceArtifacts(rendered)).toEqual([]);
  });

  test("generated Rust executes recognition, arity, load, and key dispatch", () => {
    const harnessPath = path.join(
      temporaryDirectory,
      "repl_surface_harness.rs",
    );
    const binaryPath = path.join(temporaryDirectory, "repl_surface_harness");
    const generatedPath = JSON.stringify(generatedReplSurfacePaths.rust);
    fs.writeFileSync(
      harnessPath,
      `#[path = ${generatedPath}]\nmod generated;\n\n` +
        `use generated::*;\n\n` +
        `fn main() {\n` +
        `  match classify_command_line("  .load  /project/a b.ts  ") {\n` +
        `    CommandLine::Known { command, argument } => {\n` +
        `      assert_eq!(command.id, ReplCommandId::Load);\n` +
        `      assert_eq!(argument, "/project/a b.ts  ");\n` +
        `      assert_eq!(validate_argument(command, argument), Ok(()));\n` +
        `    },\n` +
        `    other => panic!("unexpected classification: {other:?}"),\n` +
        `  }\n` +
        `  assert!(matches!(classify_command_line(".5 + 1"), CommandLine::JavaScript));\n` +
        `  assert!(matches!(classify_command_line(".help+1"), CommandLine::JavaScript));\n` +
        `  assert!(matches!(classify_command_line(".unknown x"), CommandLine::Unknown { name: ".unknown" }));\n` +
        `  let help = command_by_name(".h").unwrap();\n` +
        `  assert_eq!(help.id, ReplCommandId::Help);\n` +
        `  assert_eq!(validate_argument(help, "extra"), Err(ArgumentError::Unexpected));\n` +
        `  assert_eq!(classify_load_path("types.d.ts"), LoadDisposition::RefuseTypesOnly);\n` +
        `  assert_eq!(classify_load_path("code.ts"), LoadDisposition::Script(ParserDialect::TypeScript));\n` +
        `  assert_eq!(classify_load_path("README"), LoadDisposition::RefuseUnknownOrExtensionless);\n` +
        `  let interrupt = keybinding_for_bytes(&[3]).unwrap();\n` +
        `  assert_eq!(interrupt.id, KeybindingId::Interrupt);\n` +
        `  assert!(!interrupt.counts_as_editor_input);\n` +
        `}\n`,
    );
    const compilation = spawnSync(
      "rustc",
      ["--edition=2021", "-Dwarnings", harnessPath, "-o", binaryPath],
      { encoding: "utf8" },
    );
    expect(compilation.status, compilation.stderr).toBe(0);
    const run = spawnSync(binaryPath, [], { encoding: "utf8" });
    expect(run.status, run.stderr).toBe(0);
  });
});
