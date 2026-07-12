/**
 * Complete prerequisite matrix for an exact-target CapSec report. These broad
 * suites never satisfy individual fixture obligations by themselves; they
 * establish that the bound revision is otherwise green before fixture-specific
 * evidence is accepted.
 */
export const CONFORMANCE_COMMANDS = Object.freeze([
  ["rust-default-full", "./scripts/run-tests.sh", ["--", "--test-threads=1"]],
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
  ["hermes-transform-loader-corpora", "bun", ["run", "test:hermes-compat"]],
  ["capsec-registry-drift", "bun", ["run", "check:capsec-registry"]],
  ["capsec-contract-drift", "bun", ["run", "check:capsec-contract"]],
  ["all-generated-drift", "./scripts/check-generated-drift.sh", []],
  ["linked-literate-references", "./ref-check", []],
]);
