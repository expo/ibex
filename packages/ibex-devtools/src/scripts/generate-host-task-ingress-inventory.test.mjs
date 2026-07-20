// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam — every
// runtime-owner app-code ingress is either host-task scoped or carries a
// reviewed structural no-GPU/internal/terminal disposition.

import { afterEach, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  HOST_TASK_INGRESS_FILES,
  buildHostTaskIngressInventory,
  checkHostTaskIngressInventory,
  hostTaskIngressInventoryPath,
  repoRoot,
} from "./generate-host-task-ingress-inventory.mjs";

const temporaryRoots = [];

function copyFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-host-task-ingress-"));
  temporaryRoots.push(root);
  for (const relativePath of [
    ...HOST_TASK_INGRESS_FILES,
    "capsec/registry/host-task-ingress-inventory.json",
  ]) {
    const destination = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(repoRoot, relativePath), destination);
  }
  return root;
}

function appendSource(root, relativePath, source) {
  fs.appendFileSync(path.join(root, relativePath), `\n${source}\n`);
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("LLP 0002 host-task ingress inventory", () => {
  test("the checked artifact exactly matches the classified source inventory", () => {
    const artifact = checkHostTaskIngressInventory();
    expect(artifact.counts).toEqual({
      "user-execution-gate": 22,
      "engine-eval-or-prepare": 28,
      "jsi-function-call": 164,
    });
    expect(
      artifact.rows.reduce((count, row) => count + row.sites.length, 0),
    ).toBe(214);
    expect(artifact.ingressRows).toHaveLength(43);
    expect(
      artifact.ingressRows.find(
        (row) =>
          row.id ===
          "src/engine/hermes_runtime_gpu_v2.cc#ex_hermes_eval_gpu_canvas_app_bundle_with_prelude_immediate_v1",
      ),
    ).toMatchObject({
      disposition: "outer-host-task",
      discoveredSiteCount: 0,
    });
    expect(
      artifact.rows.find(
        (row) =>
          row.id ===
          "src/engine/hermes_runtime_debugger.cc#ex_hermes_debugger_eval",
      )?.disposition,
    ).toBe("outer-host-task");
    expect(
      artifact.rows.find(
        (row) =>
          row.id ===
          "src/engine/hermes_runtime_worklet.cc#ex_worklet_invoke",
      )?.disposition,
    ).toBe("restricted-no-app-webgpu");
    expect(fs.existsSync(hostTaskIngressInventoryPath)).toBe(true);
  });

  for (const [name, source] of [
    [
      "user-execution gate",
      "void futureHostTaskGate(ExactHermesRuntime* runtime) { (void)exactRuntimeEnterUserExecution(runtime); }",
    ],
    [
      "Hermes evaluator",
      "void futureHostTaskEval(facebook::jsi::Runtime& runtime, const std::shared_ptr<facebook::jsi::Buffer>& buffer) { (void)runtime.evaluateJavaScript(buffer, \"future\"); }",
    ],
    [
      "retained callback call",
      "void futureHostTaskCallback(const std::shared_ptr<facebook::jsi::Function>& callback, facebook::jsi::Runtime& runtime) { callback->call(runtime); }",
    ],
  ]) {
    test(`rejects a new unclassified ${name}`, () => {
      const root = copyFixture();
      appendSource(root, "src/engine/hermes_runtime_debugger.cc", source);
      expect(() => buildHostTaskIngressInventory(root)).toThrow(
        /unclassified host-task ingress sites/,
      );
    });
  }

  test("reports generated drift for a new site inside a reviewed function", () => {
    const root = copyFixture();
    const pathname = path.join(root, "src/engine/hermes_module_runner.cc");
    const source = fs.readFileSync(pathname, "utf8");
    const anchor = "auto result = entry.execute_function->call(rt);";
    expect(source.split(anchor)).toHaveLength(2);
    fs.writeFileSync(
      pathname,
      source.replace(anchor, `${anchor}\n  (void)entry.execute_function->call(rt);`),
    );
    expect(() => checkHostTaskIngressInventory({ root })).toThrow(
      /host-task-ingress-inventory\.json is stale/,
    );
  });
});
