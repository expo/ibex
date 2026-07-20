#!/usr/bin/env node

// Phase-1 checkout-local installer entry point. The library remains
// diagnostic-only until the production verifier expectation profile is wired
// in; it never turns portableArtifactAcceptanceEnabled on.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { installPortableEngine } from "./portable-engine-installer.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = path.resolve(scriptDirectory, "..");

const usage = `usage: node scripts/install-portable-hermes.mjs \\
  --archive PATH --bundle PATH --expected-source-revision 40_HEX [--repo-root PATH]

Pins and authenticates one detached portable-Hermes transport before parsing,
then safely materializes a diagnostic-only checkout-local content store.
The selected revision must be supplied by the caller's checkout authority; it
is never inferred from the archive, bundle, filename, cache, or environment.`;

function parseArguments(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(`${usage}\n`);
    return null;
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!["--archive", "--bundle", "--expected-source-revision", "--repo-root"].includes(flag) || value === undefined) {
      throw new Error(`unexpected or incomplete argument ${JSON.stringify(flag)}\n${usage}`);
    }
    if (values.has(flag)) throw new Error(`duplicate argument ${flag}`);
    values.set(flag, value);
  }
  for (const flag of ["--archive", "--bundle", "--expected-source-revision"]) {
    if (!values.has(flag)) throw new Error(`missing required argument ${flag}\n${usage}`);
  }
  return {
    repoRoot: path.resolve(values.get("--repo-root") ?? defaultRepoRoot),
    archivePath: path.resolve(values.get("--archive")),
    bundlePath: path.resolve(values.get("--bundle")),
    expectedSourceRevision: values.get("--expected-source-revision"),
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  if (!options) return;
  const result = await installPortableEngine(options);
  process.stdout.write(`${result.artifactRoot}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`install-portable-hermes: ${error.message}\n`);
    process.exitCode = 1;
  });
}
