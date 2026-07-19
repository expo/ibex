// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
// Generated bundles retain one authenticated raw-source identity per original
// module; a chunk filename is never module identity.

import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "rolldown-bundle.mjs");
const temporary = [];

afterEach(() => {
  for (const directory of temporary.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function makeDirectory() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-provenance-"));
  temporary.push(directory);
  return directory;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function authority(project, bindings = []) {
  return {
    schema: "ibex/source-provenance-authority/1",
    armedSnapshotDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    packageGraphDigest: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
    rootIdentity: { kind: "root", identity: "portable-project" },
    bindings: [
      { logicalRoot: "project", backingRoot: project },
      ...bindings,
    ],
  };
}

function bundle(project, entry, authorityValue) {
  const outputDirectory = makeDirectory();
  const output = path.join(outputDirectory, "bundle.js");
  const authorityPath = path.join(outputDirectory, "authority.json");
  const authorityBytes = Buffer.from(JSON.stringify(authorityValue), "utf8");
  fs.writeFileSync(authorityPath, authorityBytes);
  const result = Bun.spawnSync({
    cmd: [
      process.execPath,
      script,
      "--entry", entry,
      "--out", output,
      "--format", "cjs",
      "--sourcemap",
      "--cache-manifest",
      "--compartments",
      "--per-package-chunks",
      "--source-provenance-authority", authorityPath,
      "--source-provenance-authority-sha256", digest(authorityBytes),
    ],
    cwd: project,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(new TextDecoder().decode(result.stderr));
  }
  return {
    manifest: JSON.parse(fs.readFileSync(`${output}.deps.json`, "utf8")),
    output,
    authorityPath,
  };
}

function decodeSourceId(sourceId) {
  const prefix = "ibex-source-id-v1:";
  expect(sourceId.startsWith(prefix)).toBe(true);
  return JSON.parse(Buffer.from(sourceId.slice(prefix.length), "base64url").toString("utf8"));
}

describe("Rolldown per-original source provenance", () => {
  test("a multi-module chunk carries distinct raw SourceIds and no backing path", () => {
    const project = makeDirectory();
    fs.writeFileSync(
      path.join(project, "entry.js"),
      "const dep = require('./dep.js'); module.exports = dep.value + 1;\n",
    );
    fs.writeFileSync(path.join(project, "dep.js"), "exports.value = 41;\n");

    const { manifest, output } = bundle(project, "entry.js", authority(project));
    expect(manifest.version).toBe(4);
    expect(manifest.sourceProvenance.schema).toBe("ibex/source-provenance/1");
    expect(manifest.sourceProvenance.modules).toHaveLength(2);
    expect(new Set(manifest.sourceProvenance.modules.map((row) => row.sourceId)).size).toBe(2);
    expect(new Set(manifest.sourceProvenance.modules.flatMap((row) => row.chunks))).toEqual(
      new Set(["bundle.js"]),
    );
    expect(JSON.stringify(manifest.sourceProvenance)).not.toContain(project);

    const byPath = new Map(
      manifest.sourceProvenance.modules.map((row) => [row.virtualPath, row]),
    );
    for (const name of ["entry.js", "dep.js"]) {
      const row = byPath.get(`/project/${name}`);
      expect(row.sourceLabel).toBe(`file:///project/${name}`);
      expect(row.sourceSha256).toBe(manifest.deps[row.depIndex].sha256);
      expect(decodeSourceId(row.sourceId)).toEqual({
        definingPrincipal: { kind: "root", identity: "portable-project" },
        kind: "file",
        lexicalComponents: [name],
        logicalRoot: "project",
        sourceIdSchema: "ibex.source-id.v1",
      });
    }
    const sourceMap = JSON.parse(fs.readFileSync(`${output}.map`, "utf8"));
    expect(new Set(sourceMap.sources)).toEqual(new Set([
      "file:///project/entry.js",
      "file:///project/dep.js",
    ]));
    expect(sourceMap.sourceRoot).toBeUndefined();
  });

  test("package modules use the authenticated defining principal and binding-relative path", () => {
    const project = makeDirectory();
    const packageRoot = path.join(project, "node_modules", "pkg");
    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(project, "entry.js"), "module.exports = require('pkg');\n");
    fs.writeFileSync(
      path.join(packageRoot, "package.json"),
      JSON.stringify({ name: "pkg", version: "1.0.0", main: "index.js" }),
    );
    fs.writeFileSync(path.join(packageRoot, "index.js"), "module.exports = 42;\n");
    const packagePrincipal = {
      kind: "package",
      name: "pkg",
      locator: "pkg@1.0.0",
      integrity: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    };

    const { manifest } = bundle(project, "entry.js", authority(project, [{
      logicalRoot: "package",
      owner: packagePrincipal,
      backingRoot: packageRoot,
    }]));
    const module = manifest.sourceProvenance.modules.find(
      (row) => row.virtualPath === "/project/node_modules/pkg/index.js",
    );
    expect(module.bindingVirtualPrefix).toBe("/project/node_modules/pkg");
    expect(module.sourceIdentity).toEqual({
      definingPrincipal: packagePrincipal,
      logicalRoot: "package",
      lexicalComponents: ["index.js"],
    });
    expect(decodeSourceId(module.sourceId).definingPrincipal).toEqual(packagePrincipal);
  });

  test("virtual SourceLabels percent-encode UTF-8 paths exactly like raw VFS loads", () => {
    const project = makeDirectory();
    const entry = path.join(project, "entry λ.js");
    fs.writeFileSync(entry, "module.exports = 1;\n");

    const { manifest } = bundle(project, entry, authority(project));
    const module = manifest.sourceProvenance.modules.find(
      (row) => row.virtualPath === "/project/entry λ.js",
    );
    expect(module.sourceLabel).toBe("file:///project/entry%20%CE%BB.js");
  });

  test("authority tampering after digest selection fails closed", () => {
    const project = makeDirectory();
    const outputDirectory = makeDirectory();
    const entry = path.join(project, "entry.js");
    const output = path.join(outputDirectory, "bundle.js");
    const authorityPath = path.join(outputDirectory, "authority.json");
    fs.writeFileSync(entry, "module.exports = 1;\n");
    const original = Buffer.from(JSON.stringify(authority(project)), "utf8");
    fs.writeFileSync(authorityPath, original);
    fs.appendFileSync(authorityPath, " ");

    const result = Bun.spawnSync({
      cmd: [
        process.execPath,
        script,
        "--entry", entry,
        "--out", output,
        "--format", "cjs",
        "--cache-manifest",
        "--source-provenance-authority", authorityPath,
        "--source-provenance-authority-sha256", digest(original),
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(result.exitCode).not.toBe(0);
    expect(new TextDecoder().decode(result.stderr)).toContain("authority digest mismatch");
    expect(fs.existsSync(`${output}.deps.json`)).toBe(false);
  });
});
