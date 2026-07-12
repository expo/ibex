import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runObservedCommand } from "./capsec-command-evidence.mjs";

const roots = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

test("command evidence streams large output and retains only a bounded tail", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-capsec-command-"));
  roots.push(root);
  const evidence = runObservedCommand({
    id: "large-output",
    command: process.execPath,
    args: ["-e", "process.stdout.write('x'.repeat(3 * 1024 * 1024) + 'MARKER\\n')"],
    cwd: root,
    evidenceDirectory: path.join(root, "evidence"),
    tailBytes: 4096,
  });
  expect(evidence.exitCode).toBe(0);
  expect(evidence.stdout.bytes).toBeGreaterThan(3 * 1024 * 1024);
  expect(evidence.stdout.digest).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/);
  expect(evidence.stdout.truncated).toBe(true);
  expect(Buffer.byteLength(evidence.stdout.tail)).toBeLessThanOrEqual(4096);
  expect(evidence.stdout.tail).toEndWith("MARKER\n");
});
