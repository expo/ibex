/**
 * Complete prerequisite matrix for an exact-target CapSec report. These broad
 * suites never satisfy individual fixture obligations by themselves; they
 * establish that the bound revision is otherwise green before fixture-specific
 * evidence is accepted.
 */
const pythonCommand = process.platform === "win32" ? "python" : "python3";
const WINDOWS_TARGET = "x86_64-pc-windows-msvc";
const REGISTRY_GENERATOR =
  "packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs";

export function resolveConformanceMatrixInvocation({
  id,
  command,
  args,
  target,
  environment,
  repoRoot,
}) {
  if (target !== WINDOWS_TARGET) {
    return { command, args, environmentKeys: [] };
  }
  if (id === "capsec-registry-drift") {
    const nodeOracle = environment.IBEX_NODE_ORACLE_BIN;
    if (typeof nodeOracle !== "string" || nodeOracle.length === 0) {
      throw new Error(
        "Windows CapSec registry drift requires IBEX_NODE_ORACLE_BIN",
      );
    }
    return {
      command: nodeOracle,
      args: [`${repoRoot}/${REGISTRY_GENERATOR}`, "--check"],
      environmentKeys: ["IBEX_NODE_ORACLE_BIN"],
    };
  }
  if (command === "bash") {
    const gitBash = environment.IBEX_GIT_BASH_BIN;
    if (typeof gitBash !== "string" || gitBash.length === 0) {
      throw new Error(
        "Windows CapSec shell commands require IBEX_GIT_BASH_BIN",
      );
    }
    return {
      command: gitBash,
      args,
      environmentKeys: ["IBEX_GIT_BASH_BIN"],
    };
  }
  return { command, args, environmentKeys: [] };
}

export const CONFORMANCE_PREFLIGHT_COMMANDS = Object.freeze([
  ["capsec-registry-drift", "bun", ["run", "check:capsec-registry"]],
  ["capsec-contract-drift", "bun", ["run", "check:capsec-contract"]],
  ["generated-policy-drift", "bun", ["run", "check:example-policy"]],
  ["all-generated-drift", "bash", ["./scripts/check-generated-drift.sh"]],
  ["linked-literate-references", pythonCommand, ["./ref-check"]],
]);

// The performance observer is deliberately available only to the dedicated
// release iOS Simulator lane. Generic host conformance must exercise every
// other crate feature without turning that target-bound observer into an
// invalid macOS or Windows build. The adjacent contract test keeps this list
// synchronized with Cargo.toml.
export const CONFORMANCE_HOST_FEATURES = Object.freeze([
  "app-host",
  "capsec-conformance-observer",
  "cli-notify",
  "dev-committed-embedder",
  "host-http-server",
  "insecure",
  "module-runner",
  "module-runner-spike",
  "openssl-crypto",
  "runtime-extension-conformance",
  "sfe-catalog-build",
  "sfe-compiled-runtime",
  "sfe-dev-spike",
  "sfe-static-network",
  "standard",
  "tls-client-identity-openssl",
  "unadvertised-dev-arming",
]);

export const CONFORMANCE_PRODUCT_COMMANDS = Object.freeze([
  [
    "rust-default-full",
    "bash",
    ["./scripts/run-tests.sh", "--", "--test-threads=1"],
  ],
  [
    "rust-workspace-host-features-executable-tests",
    "cargo",
    [
      "test",
      "--workspace",
      "--no-default-features",
      "--features",
      CONFORMANCE_HOST_FEATURES.join(","),
      "--lib",
      "--bins",
      "--tests",
      "--examples",
      "--",
      "--test-threads=1",
    ],
  ],
  [
    "rust-workspace-host-features-all-targets-compile",
    "cargo",
    [
      "check",
      "--workspace",
      "--no-default-features",
      "--features",
      CONFORMANCE_HOST_FEATURES.join(","),
      "--all-targets",
    ],
  ],
  ["devtools-js-full", "bun", ["test", "packages/ibex-devtools/src/scripts"]],
  ["runtime-js-full", "bun", ["test", "packages/ibex-runtime-js/src"]],
  ["android-websocket-behavioral", "bash", ["./scripts/test-android-java.sh"]],
  ["hermes-transform-loader-corpora", "bun", ["run", "test:hermes-compat"]],
  [
    "runtime-environment-inventory-drift",
    "bun",
    ["run", "check:runtime-environment-inventory"],
  ],
]);

export const CONFORMANCE_COMMANDS = Object.freeze([
  ...CONFORMANCE_PREFLIGHT_COMMANDS,
  ...CONFORMANCE_PRODUCT_COMMANDS,
]);
