// The prebuilt-artifact transport must degrade, never terminate: an
// installed-but-unusable GitHub CLI has to leave the HTTPS and -Source
// fallbacks reachable. Windows PowerShell 5 turns redirected native stderr
// into a terminating NativeCommandError under $ErrorActionPreference =
// "Stop", which is how a bare `gh auth status 2>$null` probe killed the
// installer before any fallback ran.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  constants as fsConstants,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const installer = path.join(
  repoRoot,
  "scripts",
  "install-windows-hermes.ps1",
);
const powershellExecutable =
  process.platform === "win32" ? "powershell" : "pwsh";

// Resolved once so the missing-CLI probe can run the shell with a PATH that
// contains no gh at all. PATH scanning (rather than asking the shell for its
// process path) keeps wrapper launchers like Homebrew's pwsh shim working.
function resolveOnPath(name) {
  const extensions = process.platform === "win32" ? [".exe", ".cmd"] : [""];
  for (const directory of process.env.PATH.split(path.delimiter)) {
    for (const extension of extensions) {
      const candidate = path.join(directory, name + extension);
      try {
        accessSync(candidate, fsConstants.X_OK);
        return candidate;
      } catch {
        // keep scanning
      }
    }
  }
  throw new Error(`${name} not found on PATH`);
}
const powershellPath = resolveOnPath(powershellExecutable);

const installerSource = readFileSync(installer, "utf8");
const usableHelper = installerSource.match(
  /^function Test-GitHubCliUsable \{[\s\S]*?^\}/mu,
);

function writeFakeGh(directory, { exitCode, stderrLine }) {
  const posixShim = path.join(directory, "gh");
  writeFileSync(
    posixShim,
    `#!/bin/sh\n${stderrLine ? `echo '${stderrLine}' >&2\n` : ""}exit ${exitCode}\n`,
  );
  chmodSync(posixShim, 0o755);
  writeFileSync(
    path.join(directory, "gh.cmd"),
    `${stderrLine ? `@echo ${stderrLine} 1>&2\r\n` : ""}@exit /b ${exitCode}\r\n`,
  );
}

function probeUsable(fakeGhDirectory) {
  const pathValue = fakeGhDirectory
    ? `${fakeGhDirectory}${path.delimiter}${process.env.PATH}`
    : path.join(tmpdir(), "ibex-empty-path-entry");
  return spawnSync(
    powershellPath,
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
${usableHelper[0]}
if (Test-GitHubCliUsable) { "usable" } else { "unusable" }`,
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: { ...process.env, PATH: pathValue },
    },
  );
}

test("treats an unauthenticated GitHub CLI as an unavailable transport", () => {
  const fakeGhDirectory = mkdtempSync(path.join(tmpdir(), "ibex-fake-gh-"));
  try {
    writeFakeGh(fakeGhDirectory, {
      exitCode: 1,
      stderrLine:
        "You are not logged into any GitHub hosts. Run gh auth login to authenticate.",
    });
    const probe = probeUsable(fakeGhDirectory);
    assert.equal(probe.status, 0, probe.stderr);
    assert.equal(probe.stdout.trim(), "unusable");
  } finally {
    rmSync(fakeGhDirectory, { recursive: true, force: true });
  }
});

test("keeps an authenticated GitHub CLI selected as the artifact transport", () => {
  const fakeGhDirectory = mkdtempSync(path.join(tmpdir(), "ibex-fake-gh-"));
  try {
    writeFakeGh(fakeGhDirectory, { exitCode: 0, stderrLine: "" });
    const probe = probeUsable(fakeGhDirectory);
    assert.equal(probe.status, 0, probe.stderr);
    assert.equal(probe.stdout.trim(), "usable");
  } finally {
    rmSync(fakeGhDirectory, { recursive: true, force: true });
  }
});

test("treats a missing GitHub CLI as an unavailable transport", () => {
  const probe = probeUsable(null);
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout.trim(), "unusable");
});

test("routes every gh availability decision through the guarded probe", () => {
  assert.ok(usableHelper, "installer is missing Test-GitHubCliUsable");
  // The stderr-redirected inline probe is exactly the PowerShell 5
  // terminating-error shape this file exists to keep out.
  assert.doesNotMatch(installerSource, /^\s*gh auth status 2>\$null/mu);
  const callSites = installerSource.match(/Test-GitHubCliUsable/gu);
  assert.ok(
    callSites.length >= 3,
    "expected the definition plus both transport call sites",
  );
});
