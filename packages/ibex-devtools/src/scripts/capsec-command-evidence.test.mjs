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
  const evidenceDirectory = path.join(root, "evidence");
  fs.mkdirSync(evidenceDirectory, { mode: 0o700 });
  const evidence = runObservedCommand({
    id: "large-output",
    command: process.execPath,
    args: ["-e", "process.stdout.write('x'.repeat(3 * 1024 * 1024) + 'MARKER\\n')"],
    cwd: root,
    evidenceDirectory,
    tailBytes: 4096,
  });
  expect(evidence.exitCode).toBe(0);
  expect(evidence.stdout.bytes).toBeGreaterThan(3 * 1024 * 1024);
  expect(evidence.stdout.digest).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/);
  expect(evidence.stdout.truncated).toBe(true);
  expect(Buffer.byteLength(evidence.stdout.tail)).toBeLessThanOrEqual(4096);
  expect(evidence.stdout.tail).toEndWith("MARKER\n");
});

test("command evidence refuses reused logs and symlink directories", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-capsec-command-"));
  roots.push(root);
  const evidenceDirectory = path.join(root, "evidence");
  fs.mkdirSync(evidenceDirectory, { mode: 0o700 });
  const victim = path.join(root, "victim");
  fs.writeFileSync(victim, "unchanged");
  fs.symlinkSync(victim, path.join(evidenceDirectory, "owned.stdout.log"));
  expect(() =>
    runObservedCommand({
      id: "owned",
      command: process.execPath,
      args: ["-e", "console.log('must not run')"],
      cwd: root,
      evidenceDirectory,
    }),
  ).toThrow();
  expect(fs.readFileSync(victim, "utf8")).toBe("unchanged");

  const linkedDirectory = path.join(root, "linked-evidence");
  fs.symlinkSync(evidenceDirectory, linkedDirectory);
  expect(() =>
    runObservedCommand({
      id: "linked",
      command: process.execPath,
      cwd: root,
      evidenceDirectory: linkedDirectory,
    }),
  ).toThrow(/owned real directory/);
});
