import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const DEFAULT_TAIL_BYTES = 64 * 1024;

function digestAndTail(filePath, tailBytes) {
  const descriptor = fs.openSync(filePath, "r");
  try {
    const size = fs.fstatSync(descriptor).size;
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
    fs.closeSync(descriptor);
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
  fs.mkdirSync(evidenceDirectory, { recursive: true });
  const stdoutPath = path.join(evidenceDirectory, `${id}.stdout.log`);
  const stderrPath = path.join(evidenceDirectory, `${id}.stderr.log`);
  const stdout = fs.openSync(stdoutPath, "w");
  const stderr = fs.openSync(stderrPath, "w");
  let result;
  try {
    result = spawnSync(command, args, {
      cwd,
      env,
      stdio: ["ignore", stdout, stderr],
    });
  } finally {
    fs.closeSync(stdout);
    fs.closeSync(stderr);
  }
  const evidence = {
    id,
    command: [command, ...args],
    exitCode: result.status ?? -1,
    signal: result.signal ?? null,
    stdout: digestAndTail(stdoutPath, tailBytes),
    stderr: digestAndTail(stderrPath, tailBytes),
  };
  if (result.error || result.status !== 0) {
    const detail = result.error?.message ?? evidence.stderr.tail ?? evidence.stdout.tail;
    const error = new Error(`${id} failed (${evidence.exitCode}): ${detail}`);
    error.commandEvidence = evidence;
    throw error;
  }
  return evidence;
}
