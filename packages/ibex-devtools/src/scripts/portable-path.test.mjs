import { describe, expect, test } from "bun:test";
import path from "node:path";
import { portableRelativePath } from "./portable-path.mjs";

describe("portable persisted paths", () => {
  test("serializes POSIX and Windows paths to one identity", () => {
    expect(
      portableRelativePath(
        "/repo",
        "/repo/examples/app.mjs",
        path.posix,
      ),
    ).toBe("examples/app.mjs");
    expect(
      portableRelativePath(
        "D:\\repo",
        "D:\\repo\\examples\\app.mjs",
        path.win32,
      ),
    ).toBe("examples/app.mjs");
  });
});
