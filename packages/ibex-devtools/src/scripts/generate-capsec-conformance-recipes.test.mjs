import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test } from "bun:test";

import {
  main,
  parseRecipeGeneratorArgs,
} from "./generate-capsec-conformance-recipes.mjs";

test("parses generated and accepted scope bundle modes exactly", () => {
  const generated = parseRecipeGeneratorArgs([
    "--output",
    "target/generated-recipes.json",
    "--scope-output-dir",
    "target/generated-scope",
    "--scope-families",
    "lifecycle,clipboard,lifecycle",
  ]);
  expect(generated.scopeFamilies).toEqual(["clipboard", "lifecycle"]);
  expect(generated.scopeOutputDirectory).toEndWith("target/generated-scope");

  const accepted = parseRecipeGeneratorArgs([
    "--scope-input-dir",
    "target/admitted-scope",
    "--scope-output-dir",
    "target/copied-scope",
  ]);
  expect(accepted.scopeInputDirectory).toEndWith("target/admitted-scope");
  expect(() =>
    parseRecipeGeneratorArgs(["--scope-input-dir", "target/scope"]),
  ).toThrow(/requires --scope-output-dir/u);
  expect(() =>
    parseRecipeGeneratorArgs([
      "--scope-input-dir",
      "target/scope",
      "--scope-output-dir",
      "target/copied-scope",
      "--scope-families",
      "clipboard",
    ]),
  ).toThrow(/cannot be combined/u);
});

test("one producer command emits and accepts the scope companions with the bound catalog", async () => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "ibex-scoped-recipe-producer-"),
  );
  const generatedCatalogPath = path.join(temporaryRoot, "generated.json");
  const generatedScopeDirectory = path.join(temporaryRoot, "generated-scope");
  const acceptedCatalogPath = path.join(temporaryRoot, "accepted.json");
  const acceptedScopeDirectory = path.join(temporaryRoot, "accepted-scope");
  const originalLog = console.log;
  console.log = () => {};
  try {
    await main([
      "--target",
      "aarch64-apple-darwin",
      "--output",
      generatedCatalogPath,
      "--scope-output-dir",
      generatedScopeDirectory,
      "--scope-families",
      "clipboard",
    ]);
    await main([
      "--target",
      "aarch64-apple-darwin",
      "--output",
      acceptedCatalogPath,
      "--scope-input-dir",
      generatedScopeDirectory,
      "--scope-output-dir",
      acceptedScopeDirectory,
    ]);
  } finally {
    console.log = originalLog;
  }

  const generatedCatalog = JSON.parse(
    fs.readFileSync(generatedCatalogPath, "utf8"),
  );
  const generatedScope = JSON.parse(
    fs.readFileSync(
      path.join(generatedScopeDirectory, "capsec-scope.json"),
      "utf8",
    ),
  );
  expect(generatedCatalog.summary.scopeDigest).toBe(
    generatedScope.scopeDigest,
  );
  expect(generatedCatalog.summary.expandedCellIds).toEqual(
    generatedScope.expandedCellIds,
  );
  expect(fs.readFileSync(acceptedCatalogPath)).toEqual(
    fs.readFileSync(generatedCatalogPath),
  );
  for (const filename of [
    "capsec-scope.json",
    "capsec-scope-expansion-diff.json",
    "capsec-scope-cell-mapping.json",
  ]) {
    expect(fs.readFileSync(path.join(acceptedScopeDirectory, filename))).toEqual(
      fs.readFileSync(path.join(generatedScopeDirectory, filename)),
    );
  }
}, 120_000);
