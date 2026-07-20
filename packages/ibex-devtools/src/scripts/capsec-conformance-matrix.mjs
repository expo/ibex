/**
 * Complete prerequisite matrix for an exact-target CapSec report. These broad
 * suites never satisfy individual fixture obligations by themselves; they
 * establish that the bound revision is otherwise green before fixture-specific
 * evidence is accepted.
 */
const pythonCommand = process.platform === "win32" ? "python" : "python3";

export const CONFORMANCE_PREFLIGHT_COMMANDS = Object.freeze([
  ["capsec-registry-drift", "bun", ["run", "check:capsec-registry"]],
  ["capsec-contract-drift", "bun", ["run", "check:capsec-contract"]],
  ["generated-policy-drift", "bun", ["run", "check:example-policy"]],
  ["all-generated-drift", "bash", ["./scripts/check-generated-drift.sh"]],
  ["linked-literate-references", pythonCommand, ["./ref-check"]],
]);

export const CONFORMANCE_PRODUCT_COMMANDS = Object.freeze([
  [
    "rust-default-full",
    "bash",
    ["./scripts/run-tests.sh", "--", "--test-threads=1"],
  ],
  [
    "rust-workspace-all-features-executable-tests",
    "cargo",
    [
      "test",
      "--workspace",
      "--all-features",
      "--lib",
      "--bins",
      "--tests",
      "--examples",
      "--",
      "--test-threads=1",
    ],
  ],
  [
    "rust-workspace-all-features-all-targets-compile",
    "cargo",
    ["check", "--workspace", "--all-features", "--all-targets"],
  ],
  ["devtools-js-full", "bun", ["test", "packages/ibex-devtools/src/scripts"]],
  ["runtime-js-full", "bun", ["test", "packages/ibex-runtime-js/src"]],
  [
    "android-websocket-behavioral",
    "bash",
    ["./scripts/test-android-java.sh"],
  ],
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
