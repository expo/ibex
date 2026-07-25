/**
 * Canonical Cargo invocation for every authority-bearing CapSec conformance
 * test. Plain Cargo defaults are secure, but promotion evidence still pins an
 * explicit feature closure so future default changes cannot silently alter the
 * observed decision plane.
 *
 * @ref LLP 0039#secure-mode-must-stay-exercised — security evidence must run
 * with `insecure` absent.
 */

export const CAPSEC_SECURE_TEST_FEATURES =
  "standard,capsec-conformance-observer,openssl-crypto";

export function capsecSecureCargoTestCommand(testName, nocapture = false) {
  if (typeof testName !== "string" || testName.length === 0) {
    throw new Error("CapSec secure test command requires a test name");
  }
  return [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--no-default-features",
    "--features",
    CAPSEC_SECURE_TEST_FEATURES,
    testName,
    "--",
    "--test-threads=1",
    ...(nocapture ? ["--nocapture"] : []),
  ];
}
