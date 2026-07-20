#!/usr/bin/env bun

/**
 * Execute or merge exact-target inherited intrinsic alias evidence.
 *
 * A normal run performs a loaded-engine preflight, authors the probe for the
 * target the Rust binary actually reports, executes it in that loaded runtime,
 * and writes a fail-closed ledger. Receipt-bound records retain useful byte
 * and coordinate evidence, but imported JSON remains untrusted until a future
 * independent target/CI attestation contract exists. `--audit-only --record <file>`
 * merges command-bound target records without executing a local engine. Android device runners
 * can pull the Rust preflight, use `--plan-only --preflight <file>` on the
 * host, then push the resulting plan back for the execution test.
 */

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  auditInheritedIntrinsicAliasExecutionLedger,
  inheritedIntrinsicAliasExecutionPlan,
  INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_SCHEMA,
} from "./capsec-inherited-intrinsic-alias-conformance.mjs";
import { auditInheritedIntrinsicAliasSources } from "./capsec-inherited-intrinsic-alias-accounts.mjs";
import { discoverHermesEvaluatorIdentityProfiles } from "./capsec-surface-inventory.mjs";
import { runObservedCommand } from "./capsec-command-evidence.mjs";
import { canonicalJson, parseJsonStrict } from "./capsec-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const PREFLIGHT_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-loaded-engine-preflight/1";
const SOURCE_PATHS = [
  "packages/ibex-runtime-js/src/node/Buffer.ts",
  "packages/ibex-runtime-js/src/bootstrap.ts",
  "src/engine/bootstrap/compat-polyfills.js",
];

function parseArguments(argv) {
  const options = {
    auditOnly: false,
    targetRecordPaths: [],
    outputDirectory: null,
    expectedProfile: null,
    planOnly: false,
    preflightPath: null,
  };
  const valueAfter = (index, flag) => {
    const value = argv[index + 1];
    if (value === undefined) throw new Error(`${flag} needs a value`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--audit-only") options.auditOnly = true;
    else if (argument === "--plan-only") options.planOnly = true;
    else if (argument === "--record") {
      options.targetRecordPaths.push(valueAfter(index, argument));
      index += 1;
    } else if (argument === "--output-dir") {
      options.outputDirectory = valueAfter(index, argument);
      index += 1;
    } else if (argument === "--profile") {
      options.expectedProfile = valueAfter(index, argument);
      index += 1;
    } else if (argument === "--preflight") {
      options.preflightPath = valueAfter(index, argument);
      index += 1;
    } else {
      throw new Error(`unknown argument ${argument}`);
    }
  }
  if (options.auditOnly && options.planOnly) {
    throw new Error("--audit-only and --plan-only are mutually exclusive");
  }
  if (options.planOnly && !options.preflightPath) {
    throw new Error("--plan-only requires a pulled --preflight record");
  }
  return options;
}

function readJson(filePath, label) {
  const metadata = fs.lstatSync(filePath);
  const owned =
    typeof process.getuid !== "function" || metadata.uid === process.getuid();
  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    !owned
  ) {
    throw new Error(`${label} ${filePath} must be an owned regular file`);
  }
  let handle;
  try {
    handle = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(handle);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino
    ) {
      throw new Error("file identity changed while opening");
    }
    const bytes = fs.readFileSync(handle);
    const current = fs.lstatSync(filePath);
    if (
      current.isSymbolicLink() ||
      !current.isFile() ||
      current.dev !== opened.dev ||
      current.ino !== opened.ino
    ) {
      throw new Error("file identity changed while reading");
    }
    return parseJsonStrict(bytes, label);
  } catch (error) {
    throw new Error(`${label} ${filePath} is not readable JSON: ${error.message}`);
  } finally {
    if (handle !== undefined) fs.closeSync(handle);
  }
}

function writeNewJson(filePath, value) {
  const handle = fs.openSync(filePath, "wx", 0o600);
  try {
    fs.writeFileSync(handle, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
}

function prepareOutputDirectory(requestedPath) {
  if (requestedPath) {
    const resolved = path.resolve(requestedPath);
    fs.mkdirSync(resolved, { mode: 0o700, recursive: false });
    return resolved;
  }
  const targetRoot = path.join(repoRoot, "target");
  fs.mkdirSync(targetRoot, { recursive: true });
  return fs.mkdtempSync(
    path.join(targetRoot, "capsec-intrinsic-alias-evidence-"),
  );
}

function sourceAudit() {
  return auditInheritedIntrinsicAliasSources({
    sourceFiles: Object.fromEntries(
      SOURCE_PATHS.map((relativePath) => [
        relativePath,
        fs.readFileSync(path.join(repoRoot, relativePath), "utf8"),
      ]),
    ),
    engineProfiles: discoverHermesEvaluatorIdentityProfiles(repoRoot),
  });
}

function git(...args) {
  return execFileSync("git", args, { cwd: repoRoot, encoding: "utf8" }).trim();
}

function committedSourceIdentity({ requireClean }) {
  if (requireClean && git("status", "--porcelain")) {
    throw new Error(
      "inherited intrinsic target execution requires a clean committed source tree",
    );
  }
  return {
    sourceRevision: git("rev-parse", "HEAD"),
    sourceTree: git("rev-parse", "HEAD^{tree}"),
  };
}

function evidenceDigest(value) {
  return `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value))
    .digest("hex")}`;
}

function runCargoBatch({ id, testName, environment, outputDirectory }) {
  const args = [
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    testName,
    "--",
    "--test-threads=1",
    "--nocapture",
  ];
  let commandEvidence;
  try {
    commandEvidence = runObservedCommand({
      id,
      command: "cargo",
      args,
      cwd: repoRoot,
      evidenceDirectory: outputDirectory,
      env: { ...process.env, ...environment },
    });
  } catch (error) {
    commandEvidence = error.commandEvidence;
    if (commandEvidence) {
      writeNewJson(path.join(outputDirectory, `${id}.command.json`), {
        schema: "ibex/capsec-inherited-intrinsic-alias-command/1",
        evidenceEnvironment: Object.keys(environment).sort(),
        commandEvidence,
      });
    }
    throw error;
  }
  writeNewJson(path.join(outputDirectory, `${id}.command.json`), {
    schema: "ibex/capsec-inherited-intrinsic-alias-command/1",
    evidenceEnvironment: Object.keys(environment).sort(),
    commandEvidence,
  });
  return {
    schema: "ibex/capsec-inherited-intrinsic-alias-command/1",
    evidenceEnvironment: Object.keys(environment).sort(),
    commandEvidence,
  };
}

function validatePreflight(preflight, expectedProfile) {
  if (
    preflight?.schema !== PREFLIGHT_SCHEMA ||
    typeof preflight.profileId !== "string" ||
    typeof preflight.targetVariant !== "string" ||
    typeof preflight.target?.triple !== "string" ||
    !Array.isArray(preflight.target?.features) ||
    !preflight.loadedEngineIdentity ||
    !preflight.loadedEngineProfileProvenance
  ) {
    throw new Error("loaded-engine preflight is malformed");
  }
  if (expectedProfile && preflight.profileId !== expectedProfile) {
    throw new Error(
      `local target is ${preflight.profileId}, not requested profile ${expectedProfile}`,
    );
  }
}

const options = parseArguments(process.argv.slice(2));
const outputDirectory = prepareOutputDirectory(options.outputDirectory);
const audit = sourceAudit();
const targetRecords = options.targetRecordPaths.map((recordPath) =>
  readJson(path.resolve(recordPath), "inherited intrinsic target record"),
);

if (options.planOnly) {
  const preflight = readJson(
    path.resolve(options.preflightPath),
    "loaded-engine preflight",
  );
  validatePreflight(preflight, options.expectedProfile);
  const plan = inheritedIntrinsicAliasExecutionPlan({
    sourceAudit: audit,
    profileId: preflight.profileId,
    target: preflight.target,
  });
  const planPath = path.join(outputDirectory, "execution-plan.json");
  writeNewJson(planPath, plan);
  writeNewJson(path.join(outputDirectory, "runner-summary.json"), {
    schema: "ibex/capsec-inherited-intrinsic-alias-runner-summary/1",
    host: `${os.platform()}-${os.arch()}`,
    localExecution: false,
    planOnly: true,
    preflightPath: path.resolve(options.preflightPath),
    planPath,
    profileId: preflight.profileId,
    target: preflight.target,
  });
  console.log(JSON.stringify({ outputDirectory, planPath }, null, 2));
  process.exit(0);
}

let localEvidencePath = null;
let localTargetRecordPath = null;
let sourceIdentity = committedSourceIdentity({
  requireClean: !options.auditOnly,
});
if (!options.auditOnly) {
  const preflightPath = path.join(outputDirectory, "loaded-engine-preflight.json");
  runCargoBatch({
    id: "loaded-engine-preflight",
    testName: "capsec_inherited_intrinsic_alias_loaded_engine_preflight",
    environment: {
      IBEX_CAPSEC_INTRINSIC_ALIAS_PREFLIGHT_OUTPUT: preflightPath,
      IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE: "1",
    },
    outputDirectory,
  });
  const preflight = readJson(preflightPath, "loaded-engine preflight");
  validatePreflight(preflight, options.expectedProfile);

  const plan = inheritedIntrinsicAliasExecutionPlan({
    sourceAudit: audit,
    profileId: preflight.profileId,
    target: preflight.target,
  });
  const planPath = path.join(outputDirectory, "execution-plan.json");
  writeNewJson(planPath, plan);
  localEvidencePath = path.join(outputDirectory, "loaded-execution.json");
  const executionCommand = runCargoBatch({
    id: "loaded-intrinsic-alias-execution",
    testName: "capsec_inherited_intrinsic_alias_loaded_execution",
    environment: {
      IBEX_CAPSEC_INTRINSIC_ALIAS_PLAN: planPath,
      IBEX_CAPSEC_INTRINSIC_ALIAS_EVIDENCE_OUTPUT: localEvidencePath,
      IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE: "1",
    },
    outputDirectory,
  });
  const evidence = readJson(localEvidencePath, "local loaded execution");
  const finalSourceIdentity = committedSourceIdentity({ requireClean: true });
  if (canonicalJson(finalSourceIdentity) !== canonicalJson(sourceIdentity)) {
    throw new Error("source revision changed during inherited intrinsic execution");
  }
  const targetRecord = {
    schema: INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_SCHEMA,
    ...sourceIdentity,
    evidenceDigest: evidenceDigest(evidence),
    evidence,
    executionCommand,
  };
  localTargetRecordPath = path.join(
    outputDirectory,
    "loaded-execution-record.json",
  );
  writeNewJson(localTargetRecordPath, targetRecord);
  targetRecords.push(targetRecord);
}

const ledger = auditInheritedIntrinsicAliasExecutionLedger({
  sourceAudit: audit,
  targetRecords,
});
if (
  ledger.sourceRevision !== null &&
  (ledger.sourceRevision !== sourceIdentity.sourceRevision ||
    ledger.sourceTree !== sourceIdentity.sourceTree)
) {
  throw new Error("target records do not belong to the checked-out source revision");
}
const ledgerPath = path.join(outputDirectory, "execution-ledger.json");
writeNewJson(ledgerPath, ledger);
writeNewJson(path.join(outputDirectory, "runner-summary.json"), {
  schema: "ibex/capsec-inherited-intrinsic-alias-runner-summary/1",
  host: `${os.platform()}-${os.arch()}`,
  localExecution: !options.auditOnly,
  localEvidencePath,
  localTargetRecordPath,
  mergedTargetRecordPaths: options.targetRecordPaths.map((value) =>
    path.resolve(value),
  ),
  ledgerPath,
  status: ledger.status,
  acceptedProfileIds: ledger.acceptedProfileIds,
  missingProfileIds: ledger.missingProfileIds,
});

console.log(
  JSON.stringify(
    {
      outputDirectory,
      ledgerPath,
      status: ledger.status,
      acceptedProfileIds: ledger.acceptedProfileIds,
      missingProfileIds: ledger.missingProfileIds,
    },
    null,
    2,
  ),
);
