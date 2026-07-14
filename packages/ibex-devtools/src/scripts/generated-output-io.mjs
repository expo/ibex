/**
 * Confined, atomic writes for committed generated artifacts.
 *
 * A generator must never follow a repository path component or destination
 * symlink: doing so could overwrite an unrelated source file or escape the
 * checkout. Writing a temporary sibling and renaming it also breaks any
 * pre-existing hard link instead of truncating the linked inode.
 *
 * @ref LLP 0005#capability-registry-bindings — committed registry output is
 * deterministic repository state, not an ambient filesystem write target.
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
 * CapSec registry and contract generators share one fail-closed output path.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

function pathIsWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
}

function confinedPath(root, outputPath, label) {
  const resolvedRoot = path.resolve(root);
  const resolvedOutput = path.resolve(resolvedRoot, outputPath);
  if (
    resolvedOutput === resolvedRoot ||
    !pathIsWithin(resolvedRoot, resolvedOutput)
  ) {
    throw new Error(`${label}: output path escapes the repository root`);
  }
  return { resolvedRoot, resolvedOutput };
}

function assertRealPathWithin(realRoot, candidate, label) {
  const realCandidate = fs.realpathSync(candidate);
  if (!pathIsWithin(realRoot, realCandidate)) {
    throw new Error(`${label}: path resolves outside the repository root`);
  }
  return realCandidate;
}

function ensureConfinedParent(
  root,
  outputPath,
  label,
  { allowMissing = false, create = false, createdDirectories = null } = {},
) {
  const { resolvedRoot, resolvedOutput } = confinedPath(
    root,
    outputPath,
    label,
  );
  const rootStat = fs.lstatSync(resolvedRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error(`${label}: repository root must be a real directory`);
  }
  const realRoot = fs.realpathSync(resolvedRoot);
  const relativeParent = path.relative(
    resolvedRoot,
    path.dirname(resolvedOutput),
  );
  let cursor = resolvedRoot;
  let missing = false;
  for (const segment of relativeParent.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    if (missing || !fs.existsSync(cursor)) {
      if (!create) {
        if (allowMissing) {
          missing = true;
          continue;
        }
        throw new Error(`${label}: parent directory is missing`);
      }
      fs.mkdirSync(cursor);
      createdDirectories?.add(cursor);
      missing = false;
    }
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      throw new Error(`${label}: parent path contains a symbolic link`);
    }
    if (!stat.isDirectory()) {
      throw new Error(`${label}: parent path component is not a directory`);
    }
    assertRealPathWithin(realRoot, cursor, label);
  }
  return { realRoot, resolvedOutput };
}

/**
 * Validate an existing generated output without accepting symlink aliases.
 */
export function assertConfinedGeneratedFile(
  root,
  outputPath,
  label = outputPath,
) {
  const { realRoot, resolvedOutput } = ensureConfinedParent(
    root,
    outputPath,
    label,
  );
  if (!fs.existsSync(resolvedOutput)) {
    throw new Error(`${label}: output is missing`);
  }
  const stat = fs.lstatSync(resolvedOutput);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label}: output must not be a symbolic link`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label}: output is not a regular file`);
  }
  if (stat.nlink !== 1) {
    throw new Error(`${label}: output must not be hard-linked`);
  }
  const realOutput = assertRealPathWithin(realRoot, resolvedOutput, label);
  return { path: resolvedOutput, realPath: realOutput, stat };
}

function preflightDestination(root, outputPath, label, options = {}) {
  const confined = ensureConfinedParent(root, outputPath, label, options);
  if (!fs.existsSync(confined.resolvedOutput)) return confined;
  const stat = fs.lstatSync(confined.resolvedOutput);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label}: output must not be a symbolic link`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label}: output is not a regular file`);
  }
  if (stat.nlink !== 1) {
    throw new Error(`${label}: output must not be hard-linked`);
  }
  return { ...confined, mode: stat.mode & 0o777 };
}

function atomicReplace(
  root,
  outputPath,
  content,
  label,
  createdDirectories = null,
) {
  const { resolvedOutput, mode = 0o644 } = preflightDestination(
    root,
    outputPath,
    label,
    { create: true, createdDirectories },
  );
  const parent = path.dirname(resolvedOutput);
  const basename = path.basename(resolvedOutput);
  let temporaryPath;
  let descriptor;
  try {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      temporaryPath = path.join(
        parent,
        `.${basename}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`,
      );
      try {
        descriptor = fs.openSync(
          temporaryPath,
          fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
          mode,
        );
        break;
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
    }
    if (descriptor === undefined) {
      throw new Error(`${label}: unable to allocate an atomic sibling output`);
    }
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporaryPath, resolvedOutput);
    temporaryPath = undefined;
    assertConfinedGeneratedFile(root, resolvedOutput, label);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (temporaryPath && fs.existsSync(temporaryPath))
      fs.unlinkSync(temporaryPath);
  }
}

function canonicalEntries(root, entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("generated output transaction requires at least one entry");
  }
  const seen = new Set();
  return entries.map((entry, index) => {
    const label = entry.label ?? `generated output ${index}`;
    if (
      !entry ||
      (typeof entry.content !== "string" && !Buffer.isBuffer(entry.content))
    ) {
      throw new Error(`${label}: generated content must be a string or Buffer`);
    }
    const { resolvedOutput } = preflightDestination(root, entry.path, label, {
      allowMissing: true,
    });
    if (seen.has(resolvedOutput)) {
      throw new Error(`${label}: duplicate generated output path`);
    }
    seen.add(resolvedOutput);
    return { ...entry, label, path: resolvedOutput };
  });
}

/**
 * Replace each member of a closed generated-output family atomically. If a
 * later write or caller-supplied synchronous semantic validation fails,
 * restore every original byte and remove parents created by the transaction.
 */
export function writeGeneratedFilesTransactionally(
  root,
  entries,
  validate = () => undefined,
) {
  const normalized = canonicalEntries(root, entries);
  const createdDirectories = new Set();
  const originals = normalized.map((entry) => ({
    entry,
    existed: fs.existsSync(entry.path),
    content: fs.existsSync(entry.path) ? fs.readFileSync(entry.path) : null,
  }));
  try {
    for (const entry of normalized) {
      atomicReplace(
        root,
        entry.path,
        entry.content,
        entry.label,
        createdDirectories,
      );
    }
    const validationResult = validate();
    if (
      validationResult !== null &&
      (typeof validationResult === "object" ||
        typeof validationResult === "function") &&
      typeof validationResult.then === "function"
    ) {
      // Mark a rejected Promise handled before throwing synchronously and
      // rolling back. This helper deliberately has no async commit window.
      Promise.resolve(validationResult).catch(() => undefined);
      throw new Error(
        "generated output transaction validation must be synchronous",
      );
    }
    return validationResult;
  } catch (error) {
    const rollbackErrors = [];
    for (const original of [...originals].reverse()) {
      try {
        if (original.existed) {
          atomicReplace(
            root,
            original.entry.path,
            original.content,
            `${original.entry.label} rollback`,
            createdDirectories,
          );
        } else if (fs.existsSync(original.entry.path)) {
          const current = fs.lstatSync(original.entry.path);
          if (current.isSymbolicLink() || !current.isFile()) {
            throw new Error("new output changed type during rollback");
          }
          fs.unlinkSync(original.entry.path);
        }
      } catch (rollbackError) {
        rollbackErrors.push(
          `${original.entry.label}: ${rollbackError.message}`,
        );
      }
    }
    for (const directory of [...createdDirectories].sort(
      (left, right) => right.length - left.length,
    )) {
      try {
        if (!fs.existsSync(directory)) continue;
        const stat = fs.lstatSync(directory);
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
          throw new Error("created parent changed type during rollback");
        }
        fs.rmdirSync(directory);
      } catch (rollbackError) {
        rollbackErrors.push(`${directory}: ${rollbackError.message}`);
      }
    }
    if (rollbackErrors.length > 0) {
      throw new AggregateError(
        [error, ...rollbackErrors.map((message) => new Error(message))],
        `generated output transaction failed and rollback was incomplete: ${rollbackErrors.join("; ")}`,
      );
    }
    throw error;
  }
}
