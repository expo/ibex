import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — suite
// output is promotion evidence, so retain it only through private files whose
// identity cannot be redirected during execution.

const DEFAULT_TAIL_BYTES = 64 * 1024;

// Evidence IDs become filenames and therefore use a deliberately smaller
// alphabet than content digests. Keep the full SHA-256 in lowercase hex: this
// is canonical under the ID grammar without folding base64url characters and
// losing collision resistance.
export function commandEvidenceIdSuffix(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const ownedByCurrentUser = (metadata) =>
  typeof process.getuid !== "function" || metadata.uid === process.getuid();

function assertOwnedRegularPath(filePath, opened) {
  const current = fs.lstatSync(filePath);
  if (
    current.isSymbolicLink() ||
    !current.isFile() ||
    current.nlink !== 1 ||
    !ownedByCurrentUser(current) ||
    current.dev !== opened.dev ||
    current.ino !== opened.ino
  ) {
    throw new Error(
      `${filePath}: command log identity changed during execution`,
    );
  }
}

function openOwnedLog(filePath) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      fs.constants.O_RDWR |
      (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  const stat = fs.fstatSync(descriptor);
  if (!stat.isFile() || stat.nlink !== 1 || !ownedByCurrentUser(stat)) {
    fs.closeSync(descriptor);
    throw new Error(`${filePath}: command log is not a new regular file`);
  }
  return { descriptor, stat };
}

function digestAndTail(filePath, descriptor, opened, tailBytes) {
  assertOwnedRegularPath(filePath, opened);
  const current = fs.fstatSync(descriptor);
  if (
    !current.isFile() ||
    current.nlink !== 1 ||
    current.dev !== opened.dev ||
    current.ino !== opened.ino
  ) {
    throw new Error(`${filePath}: opened command log identity changed`);
  }
  const size = current.size;
  try {
    const hash = crypto.createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < size) {
      const read = fs.readSync(
        descriptor,
        chunk,
        0,
        Math.min(chunk.length, size - offset),
        offset,
      );
      if (read === 0) break;
      hash.update(chunk.subarray(0, read));
      offset += read;
    }
    const tailLength = Math.min(size, tailBytes);
    const tail = Buffer.alloc(tailLength);
    if (tailLength > 0) {
      fs.readSync(descriptor, tail, 0, tailLength, size - tailLength);
    }
    return {
      bytes: size,
      digest: `sha256-${hash.digest("base64url")}`,
      tail: tail.toString("utf8"),
      truncated: size > tailLength,
    };
  } finally {
    assertOwnedRegularPath(filePath, opened);
  }
}

export function runObservedCommand({
  id,
  command,
  args = [],
  cwd,
  evidenceDirectory,
  env = process.env,
  tailBytes = DEFAULT_TAIL_BYTES,
}) {
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(id)) {
    throw new Error(`invalid command evidence id ${JSON.stringify(id)}`);
  }
  const directory = fs.lstatSync(evidenceDirectory);
  if (
    directory.isSymbolicLink() ||
    !directory.isDirectory() ||
    !ownedByCurrentUser(directory) ||
    (directory.mode & 0o077) !== 0
  ) {
    throw new Error(
      "command evidence directory must be an owned real directory",
    );
  }
  const stdoutPath = path.join(evidenceDirectory, `${id}.stdout.log`);
  const stderrPath = path.join(evidenceDirectory, `${id}.stderr.log`);
  const stdout = openOwnedLog(stdoutPath);
  let stderr;
  let result;
  try {
    stderr = openOwnedLog(stderrPath);
    result = spawnSync(command, args, {
      cwd,
      env,
      stdio: ["ignore", stdout.descriptor, stderr.descriptor],
    });
    fs.fsyncSync(stdout.descriptor);
    fs.fsyncSync(stderr.descriptor);
    const evidence = {
      id,
      command: [command, ...args],
      exitCode: result.status ?? -1,
      signal: result.signal ?? null,
      stdout: digestAndTail(
        stdoutPath,
        stdout.descriptor,
        stdout.stat,
        tailBytes,
      ),
      stderr: digestAndTail(
        stderrPath,
        stderr.descriptor,
        stderr.stat,
        tailBytes,
      ),
    };
    if (result.error || result.status !== 0) {
      const detail =
        result.error?.message ?? evidence.stderr.tail ?? evidence.stdout.tail;
      const error = new Error(`${id} failed (${evidence.exitCode}): ${detail}`);
      error.commandEvidence = evidence;
      throw error;
    }
    return evidence;
  } finally {
    fs.closeSync(stdout.descriptor);
    if (stderr) fs.closeSync(stderr.descriptor);
  }
}
