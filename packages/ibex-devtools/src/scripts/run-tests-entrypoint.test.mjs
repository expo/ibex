import { expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

test("the fail-loud test wrapper binds native build tools under Git Bash", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-run-tests-msvc-"));
  try {
    const toolsRoot = path.join(temporary, "msvc");
    const linker = path.join(toolsRoot, "bin", "Hostx64", "x64", "link.exe");
    fs.mkdirSync(path.dirname(linker), { recursive: true });
    fs.writeFileSync(linker, "");

    const perlBin = path.join(temporary, "strawberry", "bin");
    const perl = path.join(perlBin, "perl.exe");
    fs.mkdirSync(perlBin, { recursive: true });
    fs.writeFileSync(perl, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });

    const fakeBin = path.join(temporary, "bin");
    const capture = path.join(temporary, "linker.txt");
    const cargo = path.join(fakeBin, "cargo");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(
      cargo,
      `#!/usr/bin/env bash
printf '%s' "$CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER" > "$IBEX_TEST_LINKER_CAPTURE"
printf '%s' "$OPENSSL_SRC_PERL" > "$IBEX_TEST_PERL_CAPTURE"
printf 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n'
`,
      { mode: 0o755 },
    );

    const result = spawnSync(
      "bash",
      [path.join(repoRoot, "scripts", "run-tests.sh"), "--scope", "lib"],
      {
        cwd: repoRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
          OS: "Windows_NT",
          OPENSSL_SRC_PERL: "",
          PERL: "",
          VCToolsInstallDir: `${toolsRoot}${path.sep}`,
          VSCMD_ARG_HOST_ARCH: "x64",
          VSCMD_ARG_TGT_ARCH: "x64",
          __VSCMD_PREINIT_PATH: `${path.join(temporary, "missing")};${perlBin}`,
          IBEX_TEST_LINKER_CAPTURE: capture,
          IBEX_TEST_PERL_CAPTURE: path.join(temporary, "perl.txt"),
        },
      },
    );

    expect(result.status).toBe(0);
    expect(result.stderr).toContain("run-tests: ran 1 tests");
    expect(fs.readFileSync(capture, "utf8")).toBe(linker);
    expect(
      fs.readFileSync(path.join(temporary, "perl.txt"), "utf8"),
    ).toBe(perl);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
