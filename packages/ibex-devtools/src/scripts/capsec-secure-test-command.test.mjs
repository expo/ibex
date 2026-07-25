import { describe, expect, test } from "bun:test";
import {
  CAPSEC_SECURE_TEST_FEATURES,
  capsecSecureCargoTestCommand,
} from "./capsec-secure-test-command.mjs";
import { PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS } from "./capsec-public-executors.mjs";

describe("CapSec secure conformance commands", () => {
  test("pins the production profile and excludes insecure mode", () => {
    const command = capsecSecureCargoTestCommand("proof_test", true);
    expect(command).toEqual([
      "cargo",
      "test",
      "--bin",
      "ibex",
      "--no-default-features",
      "--features",
      CAPSEC_SECURE_TEST_FEATURES,
      "proof_test",
      "--",
      "--test-threads=1",
      "--nocapture",
    ]);
    expect(CAPSEC_SECURE_TEST_FEATURES.split(",")).toContain("standard");
    expect(CAPSEC_SECURE_TEST_FEATURES.split(",")).not.toContain("insecure");
  });

  test("routes every promotion-facing executor through the secure command", () => {
    for (const descriptor of PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS) {
      expect(descriptor.command).toContain("--no-default-features");
      expect(descriptor.command).toContain(CAPSEC_SECURE_TEST_FEATURES);
      expect(descriptor.command).not.toContain("insecure");
    }
  });
});
