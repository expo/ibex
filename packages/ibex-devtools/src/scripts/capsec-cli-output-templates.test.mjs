import { describe, expect, test } from "bun:test";
import {
  authoredCliOutputInvocation,
  compiledCliEvidenceTypes,
} from "./capsec-cli-output-templates.mjs";

function surface(name, evidenceType, metadata = {}) {
  return {
    kind: "cli",
    name,
    observedKey: `cli:${name}`,
    sourceRefs: [`runtime-surface.json#${name}`],
    metadata: { evidenceType, ...metadata },
  };
}

const coverageEdge = {
  id: "surface.cli.test.0000001",
  classification: "non-capability",
};

describe("compiled CLI output recipes", () => {
  test("authors a source-only Clap read without expected value echo", () => {
    const invocation = authoredCliOutputInvocation({
      surface: surface("option:ibex:inspect:action:SetTrue", "cli-value-action", {
        action: "SetTrue",
      }),
      coverageEdge,
    });
    expect(invocation).toMatchObject({
      invocationSchema: "ibex/capsec-cli-output-invocation/1",
      kind: "cli-output",
      coverageEdgeId: coverageEdge.id,
      operation: { kind: "clap-surface-read" },
      completion: { kind: "synchronous-compiled-runtime" },
      sourceDescriptor: {
        kind: "compiled-cli-surface",
        surfaceName: "option:ibex:inspect:action:SetTrue",
        evidenceType: "cli-value-action",
      },
    });
    expect(JSON.stringify(invocation)).not.toContain('"action":"SetTrue"');
  });

  test("does not copy a load extension disposition into the plan", () => {
    const invocation = authoredCliOutputInvocation({
      surface: surface("repl-load-extension:.cjs", "repl-load-extension", {
        disposition: "refuse-module-kind",
        errorCode: "load-module-kind",
      }),
      coverageEdge,
    });
    expect(invocation.operation).toEqual({ kind: "repl-surface-read" });
    expect(JSON.stringify(invocation)).not.toContain("disposition");
    expect(JSON.stringify(invocation)).not.toContain("load-module-kind");
  });

  test("rejects uncatalogued compiled CLI evidence families", () => {
    expect(
      authoredCliOutputInvocation({
        surface: surface("unknown", "unreviewed-cli-evidence"),
        coverageEdge,
      }),
    ).toBeNull();
    expect(compiledCliEvidenceTypes).toHaveLength(19);
  });

  test("routes manifest command names through their compiled owner", () => {
    const visible = surface("run", undefined);
    visible.metadata = {};
    visible.sourceRefs = ["runtime-surface.json#visibleCommands"];
    expect(
      authoredCliOutputInvocation({ surface: visible, coverageEdge }).operation,
    ).toEqual({ kind: "clap-command-name-read" });

    const reserved = surface("test", undefined);
    reserved.metadata = {};
    reserved.sourceRefs = ["runtime-surface.json#reservedCommands"];
    expect(
      authoredCliOutputInvocation({ surface: reserved, coverageEdge }).operation,
    ).toEqual({ kind: "namespace-command-name-read" });
  });

  test("routes product ingress through the compiled decision table", () => {
    for (const [name, sourceRef] of [
      [
        "authenticated-direct-file-ingress",
        "src/bin/ibex/main.rs#run_file_with_execution_adapter",
      ],
      ["authenticated-one-shot-ingress", "src/bin/ibex/main.rs#eval_code"],
      [
        "authenticated-program-stdin-ingress",
        "src/bin/ibex/main.rs#run_stdin_program",
      ],
      ["authenticated-repl-ingress", "src/bin/ibex/main.rs#start_repl"],
      ["implicit-no-file-dispatch", "src/bin/ibex/main.rs#run"],
    ]) {
      const product = surface(name, undefined);
      product.metadata = {};
      product.sourceRefs = [sourceRef];
      const invocation = authoredCliOutputInvocation({
        surface: product,
        coverageEdge,
      });
      expect(invocation).toMatchObject({
        operation: { kind: "product-ingress-route-read" },
        sourceDescriptor: { evidenceType: "cli-product-ingress" },
      });
    }
  });

  test("binds direct-file evidence to the reviewed execution adapter", () => {
    const direct = surface("authenticated-direct-file-ingress", undefined);
    direct.metadata = {};
    direct.sourceRefs = [
      "src/bin/ibex/main.rs#run_file_with_execution_adapter",
    ];
    expect(
      authoredCliOutputInvocation({ surface: direct, coverageEdge }),
    ).toMatchObject({
      operation: { kind: "product-ingress-route-read" },
      sourceDescriptor: {
        evidenceType: "cli-product-ingress",
        sourceRefs: [
          "src/bin/ibex/main.rs#run_file_with_execution_adapter",
        ],
      },
    });

    direct.sourceRefs = ["src/bin/ibex/main.rs#run_file"];
    expect(
      authoredCliOutputInvocation({ surface: direct, coverageEdge }),
    ).toBeNull();
  });
});
