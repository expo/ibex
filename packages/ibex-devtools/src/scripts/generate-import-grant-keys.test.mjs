// @ref LLP 0022#6-imports-and-authority — the runtime refusal set is
// generated from the build parser's exact key vocabulary, plus legacy `needs`.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import {
  checkImportGrantKeyArtifacts,
  generatedImportGrantKeyPaths,
  importGrantKeys,
  renderImportGrantKeyArtifacts,
} from "./generate-import-grant-keys.mjs";

describe("generated import-grant refusal keys", () => {
  test("projects every current and historical spelling in fixed source order", () => {
    expect(importGrantKeys()).toEqual([
      "authorities",
      "grants",
      "endow",
      "builtins",
      "also",
      "needs",
    ]);
  });

  test("renders both runtime languages from one set", () => {
    const rendered = renderImportGrantKeyArtifacts();
    for (const key of rendered.keys) {
      expect(rendered.rust).toContain(JSON.stringify(key));
      expect(rendered.javascript).toContain(JSON.stringify(key));
    }
    expect(rendered.rust).toContain("RESERVED_IMPORT_GRANT_KEYS");
    expect(rendered.javascript).toContain("__exactGeneratedImportGrantKeys");
  });

  test("committed projections are current", () => {
    const rendered = renderImportGrantKeyArtifacts();
    expect(checkImportGrantKeyArtifacts(rendered)).toEqual([]);
    expect(fs.existsSync(generatedImportGrantKeyPaths.rust)).toBe(true);
    expect(fs.existsSync(generatedImportGrantKeyPaths.javascript)).toBe(true);
  });

  test("duplicates and malformed authoritative keys fail closed", () => {
    expect(() => importGrantKeys(["grants", "grants"])).toThrow("unique");
    expect(() => importGrantKeys(["not-a-static-key"])).toThrow("identifier");
    expect(() => importGrantKeys(["needs"])).toThrow("unique");
  });
});
