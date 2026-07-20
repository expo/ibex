import { expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const artifactWorkflow = fs.readFileSync(
  path.join(repoRoot, ".github/workflows/hermes-artifacts.yml"),
  "utf8",
);
const conformanceWorkflow = fs.readFileSync(
  path.join(repoRoot, ".github/workflows/compartment-conformance.yml"),
  "utf8",
);

// @ref LLP 0005#prebuilt-hermes-artifact-bundles — cache identity excludes
// build authority, so an existing Windows asset must be reopened before reuse.
test("Windows Hermes cache hits reopen the reviewed artifact authority", () => {
  expect(artifactWorkflow).toContain('- ".gitattributes"');
  expect(artifactWorkflow).toContain('- "scripts/install-windows-hermes.ps1"');
  expect(artifactWorkflow).toContain(
    'gh release download "$tag" --repo "$GITHUB_REPOSITORY"',
  );
  expect(artifactWorkflow).toContain(
    'unzip -p "$tmp/$windows_asset" artifact.json',
  );
  expect(artifactWorkflow).toContain(".sourceBuildAuthorityDigest");
  expect(artifactWorkflow).toContain(
    'sha256sum scripts/build-hermes-windows.ps1',
  );
  expect(artifactWorkflow).toContain('[ "$configuration" != "Release" ]');
  expect(artifactWorkflow).toContain('[ "$debugger" != "false" ]');
  expect(artifactWorkflow).toContain(
    "Existing Windows bundle could not be revalidated; scheduling a rebuild.",
  );
  expect(artifactWorkflow).toContain("need_windows=true");
  expect(artifactWorkflow).toContain(
    'gh release upload $env:TAG $asset "$asset.sha256" --repo $env:GITHUB_REPOSITORY --clobber',
  );
});

test("verified Windows source builds survive later matrix failures", () => {
  const windowsJob = conformanceWorkflow.slice(
    conformanceWorkflow.indexOf("conformance-windows:"),
  );
  expect(windowsJob).toContain("id: windows-hermes-cache");
  expect(windowsJob).toContain("uses: actions/cache/restore@v4");
  expect(windowsJob).toContain(
    "if: steps.windows-hermes-cache.outputs.cache-hit != 'true'",
  );
  expect(windowsJob).toContain("uses: actions/cache/save@v4");
  expect(windowsJob.indexOf("uses: actions/cache/save@v4")).toBeLessThan(
    windowsJob.indexOf(
      "name: Run the complete CapSec matrix and bind evidence",
    ),
  );
});

test("Windows Git Bash suites retain the configured MSVC linker", () => {
  const windowsJob = conformanceWorkflow.slice(
    conformanceWorkflow.indexOf("conformance-windows:"),
  );
  const msvcSetup = windowsJob.indexOf("uses: ilammy/msvc-dev-cmd@v1");
  const linkerBinding = windowsJob.indexOf(
    "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=$linker",
  );

  expect(msvcSetup).toBeGreaterThanOrEqual(0);
  expect(linkerBinding).toBeGreaterThan(msvcSetup);
  expect(windowsJob).toContain('$env:VCToolsInstallDir "bin\\Hostx64\\x64\\link.exe"');
});

test("Windows conformance binds the verified Hermes CLI for product corpora", () => {
  const windowsJob = conformanceWorkflow.slice(
    conformanceWorkflow.indexOf("conformance-windows:"),
  );
  const artifactVerification = windowsJob.indexOf(
    "name: Verify cached Hermes is patched and debugger-free",
  );
  const cliBinding = windowsJob.indexOf('"IBEX_HERMES_BIN=$hermesCli"');
  const matrix = windowsJob.indexOf(
    "name: Run the complete CapSec matrix and bind evidence",
  );

  expect(windowsJob).toContain('$install "bin\\hermes.exe"');
  expect(windowsJob).toContain(
    "Windows Hermes CLI is missing from the verified artifact",
  );
  expect(windowsJob).toContain("& $hermesCli --help | Out-Null");
  expect(windowsJob).toContain(
    "Windows Hermes CLI failed its executable preflight",
  );
  expect(cliBinding).toBeGreaterThan(artifactVerification);
  expect(cliBinding).toBeLessThan(matrix);
});

test("Windows conformance can isolate module-semantics evidence", () => {
  const windowsJob = conformanceWorkflow.slice(
    conformanceWorkflow.indexOf("conformance-windows:"),
  );

  expect(conformanceWorkflow).toContain("- module-semantics");
  expect(windowsJob).toContain("name: Run focused module-semantics baseline");
  expect(windowsJob).toContain("inputs.scope == 'module-semantics'");
  expect(windowsJob).toContain("cargo test --test module_semantics_baseline");
  expect(windowsJob).toContain('"module-semantics.log"');
  expect(windowsJob).toContain(
    "IBEX_MODULE_SEMANTICS_OBSERVATIONS_OUTPUT",
  );
  expect(windowsJob).toContain('"module-semantics-observations.json"');
});

test("Windows conformance can isolate native DNS fidelity evidence", () => {
  const windowsJob = conformanceWorkflow.slice(
    conformanceWorkflow.indexOf("conformance-windows:"),
  );

  expect(conformanceWorkflow).toContain("- dns");
  expect(windowsJob).toContain("name: Run focused native DNS fidelity suite");
  expect(windowsJob).toContain("inputs.scope == 'dns'");
  expect(windowsJob).toContain("cargo test --test native_dns_rcode");
  expect(windowsJob).toContain('"native-dns-rcode.log"');
});

test("Windows conformance can isolate target-absence evidence", () => {
  const windowsJob = conformanceWorkflow.slice(
    conformanceWorkflow.indexOf("Complete matrix + unadvertised evidence (Windows x64)"),
  );
  expect(conformanceWorkflow).toContain("- target-absence");
  expect(windowsJob).toContain("name: Run focused target-absence evidence");
  expect(windowsJob).toContain("inputs.scope == 'target-absence'");
  expect(windowsJob).toContain("capsec_public_target_absence_batch");
  expect(windowsJob).toContain('"target-absence-evidence.json"');
  expect(windowsJob).toContain('"target-absence.log"');
});
