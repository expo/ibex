// @ref LLP 0021#generated-semantic-datasets — target promotion must name the
// exact source-derived implementation branches whose fixtures were executed.

import { describe, expect, test } from "bun:test";
import {
  applicableImplementationBranchIds,
  targetApplicabilityForVariant,
  targetOperatingSystem,
} from "./capsec-target-branches.mjs";

const target = (triple) => ({ triple, features: [] });
const branch = (branchId, targetVariant) => ({
  branchId,
  targetVariant,
  targetApplicability: targetApplicabilityForVariant(targetVariant),
});

describe("capsec implementation target branches", () => {
  test("derives operating systems from exact Rust-style triples", () => {
    expect(targetOperatingSystem(target("aarch64-apple-darwin"))).toBe("macos");
    expect(targetOperatingSystem(target("aarch64-apple-ios"))).toBe("ios");
    expect(targetOperatingSystem(target("aarch64-linux-android"))).toBe(
      "android",
    );
    expect(targetOperatingSystem(target("armv7-linux-androideabi"))).toBe(
      "android",
    );
    expect(targetOperatingSystem(target("thumbv7neon-linux-androideabi"))).toBe(
      "android",
    );
    expect(targetOperatingSystem(target("x86_64-pc-windows-msvc"))).toBe(
      "windows",
    );
    expect(targetOperatingSystem(target("aarch64-pc-windows-gnullvm"))).toBe(
      "windows",
    );
    expect(targetOperatingSystem(target("x86_64-unknown-linux-gnu"))).toBe(
      "linux",
    );
    expect(() =>
      targetOperatingSystem(target("wasm32-unknown-unknown")),
    ).toThrow(/unsupported target triple/);
    expect(() =>
      targetOperatingSystem(target("aarch64-apple-darwin-windows-msvc")),
    ).toThrow(/unsupported target triple/);
  });

  test("normalizes only reviewed applicability labels", () => {
    expect(targetApplicabilityForVariant("macos")).toEqual({
      kind: "operating-system",
      value: "macos",
    });
    expect(targetApplicabilityForVariant("conditional:EXACT_IPC_FD")).toEqual({
      kind: "build-condition",
      value: "EXACT_IPC_FD",
    });
    expect(targetApplicabilityForVariant("linux:libcurl")).toEqual({
      kind: "linux-backend",
      value: "libcurl",
    });
    expect(targetApplicabilityForVariant("linux")).toEqual({
      kind: "operating-system",
      value: "linux",
    });
    expect(() => targetApplicabilityForVariant("future-platform")).toThrow(
      /unreviewed implementation target variant/,
    );
  });

  test("prefers exact platform, then family, then fallback branches", () => {
    const rows = [
      branch("edge.apple", "apple"),
      branch("edge.default", "default"),
      branch("edge.macos", "macos"),
      branch("edge.posix", "posix"),
      branch("edge.windows", "windows"),
    ];
    expect(
      applicableImplementationBranchIds(rows, target("aarch64-apple-darwin")),
    ).toEqual(["edge.macos"]);
    expect(
      applicableImplementationBranchIds(
        rows.filter((row) => row.targetVariant !== "macos"),
        target("aarch64-apple-darwin"),
      ),
    ).toEqual(["edge.apple"]);
    expect(
      applicableImplementationBranchIds(
        rows.filter(
          (row) =>
            row.targetVariant !== "macos" && row.targetVariant !== "apple",
        ),
        target("aarch64-apple-darwin"),
      ),
    ).toEqual(["edge.posix"]);
    expect(
      applicableImplementationBranchIds(rows, target("x86_64-pc-windows-msvc")),
    ).toEqual(["edge.windows"]);
    expect(
      applicableImplementationBranchIds(
        [branch("edge.android", "android")],
        target("aarch64-apple-darwin"),
      ),
    ).toEqual([]);
  });

  test("retains universal, runtime, condition, and all Linux backend branches", () => {
    const rows = [
      branch("edge.all", "all"),
      branch("edge.binary", "binary"),
      branch("edge.condition", "conditional:EXACT_FLAG"),
      branch("edge.curl", "linux:curl-cli-fallback"),
      branch("edge.libcurl", "linux:libcurl"),
    ];
    expect(
      applicableImplementationBranchIds(
        rows,
        target("x86_64-unknown-linux-gnu"),
      ),
    ).toEqual([
      "edge.all",
      "edge.binary",
      "edge.condition",
      "edge.curl",
      "edge.libcurl",
    ]);
  });

  test("rejects drift between raw and normalized applicability", () => {
    const row = branch("edge.macos", "macos");
    row.targetApplicability = { kind: "operating-system", value: "android" };
    expect(() =>
      applicableImplementationBranchIds([row], target("aarch64-apple-darwin")),
    ).toThrow(/target applicability disagrees/);
  });
});
