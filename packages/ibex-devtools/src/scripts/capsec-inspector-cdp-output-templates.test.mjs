// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
// every CDP route is structural in the armed profile because startup refuses
// inspector configuration before the listener or backend can exist.

import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import { repoRoot } from "./capsec-contract.mjs";
import {
  INSPECTOR_CDP_OUTPUT_CATALOG_BINDINGS,
  INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA,
  INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
  auditInspectorCdpStructuralClosure,
  authoredInspectorCdpStructuralAccount,
  inspectorCdpStructuralAccountBindings,
  validateInspectorCdpStructuralAccount,
  validateInspectorCdpStructuralCatalog,
} from "./capsec-inspector-cdp-output-templates.mjs";
import { scanCdpSurfaces } from "./capsec-surface-inventory.mjs";

const REQUIRED_PATHS = [
  "src/bin/ibex/main.rs",
  "src/bin/ibex/runtime.rs",
  "src/bin/ibex/engine/hermes.rs",
  "src/bin/ibex/cdp/mod.rs",
];

const EXPECTED_SURFACES = [
  "inspector.cdp-http:/json",
  "inspector.cdp-http:/json/list",
  "inspector.cdp-http:/json/version",
  "inspector.cdp-listener",
  "inspector.cdp-request-fallback:json-rpc-error--32601",
  "inspector.cdp-request:Debugger.enable",
  "inspector.cdp-request:Debugger.evaluateOnCallFrame",
  "inspector.cdp-request:Debugger.getScriptSource",
  "inspector.cdp-request:Debugger.pause",
  "inspector.cdp-request:Debugger.removeBreakpoint",
  "inspector.cdp-request:Debugger.resume",
  "inspector.cdp-request:Debugger.setBreakpointByUrl",
  "inspector.cdp-request:Debugger.stepInto",
  "inspector.cdp-request:Debugger.stepOut",
  "inspector.cdp-request:Debugger.stepOver",
  "inspector.cdp-request:Log.enable",
  "inspector.cdp-request:Network.disable",
  "inspector.cdp-request:Network.enable",
  "inspector.cdp-request:Network.getResponseBody",
  "inspector.cdp-request:Page.enable",
  "inspector.cdp-request:Runtime.enable",
  "inspector.cdp-request:Runtime.evaluate",
  "inspector.cdp-request:Runtime.runIfWaitingForDebugger",
].sort();

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function sourceFixture() {
  const sourceFiles = Object.fromEntries(
    REQUIRED_PATHS.map((relativePath) => [relativePath, read(relativePath)]),
  );
  const binaryRoot = path.join(repoRoot, "src/bin/ibex");
  const binaryRustSources = Object.fromEntries(
    fs
      .readdirSync(binaryRoot, { recursive: true })
      .filter((relativePath) => String(relativePath).endsWith(".rs"))
      .map((relativePath) => {
        const absolutePath = path.join(binaryRoot, String(relativePath));
        const repositoryPath = path
          .relative(repoRoot, absolutePath)
          .split(path.sep)
          .join("/");
        return [repositoryPath, fs.readFileSync(absolutePath, "utf8")];
      }),
  );
  return { sourceFiles, binaryRustSources };
}

const source = sourceFixture();
const audit = auditInspectorCdpStructuralClosure(source);
const cdpSurfaces = scanCdpSurfaces(
  source.sourceFiles["src/bin/ibex/cdp/mod.rs"],
  "src/bin/ibex/cdp/mod.rs",
);
const coverage = JSON.parse(read("capsec/registry/coverage-edges.json"));
const edgesByObservedKey = new Map(
  coverage.edges.map((edge) => [
    `${edge.surface.kind}:${edge.surface.name}`,
    edge,
  ]),
);

describe("inspector CDP structural output accounts", () => {
  test("closes all 23 source-discovered CDP surfaces before dispatch", () => {
    expect(Object.keys(audit.surfaces).sort()).toEqual(EXPECTED_SURFACES);
    expect(cdpSurfaces.map((surface) => surface.name).sort()).toEqual(
      EXPECTED_SURFACES,
    );
    expect(
      cdpSurfaces.filter((surface) =>
        surface.name.startsWith("inspector.cdp-http:"),
      ),
    ).toHaveLength(3);
    expect(
      cdpSurfaces.filter((surface) =>
        surface.name.startsWith("inspector.cdp-request:"),
      ),
    ).toHaveLength(18);
    expect(
      cdpSurfaces.filter((surface) =>
        surface.name.startsWith("inspector.cdp-request-fallback:"),
      ),
    ).toHaveLength(1);

    const accounts = cdpSurfaces.map((surface) => {
      const coverageEdge = edgesByObservedKey.get(surface.observedKey);
      expect(coverageEdge).toBeDefined();
      const account = authoredInspectorCdpStructuralAccount({
        surface,
        coverageEdge,
        sourceAudit: audit,
      });
      expect(
        validateInspectorCdpStructuralAccount(account, {
          surface,
          coverageEdge,
          sourceAudit: audit,
        }),
      ).toBe(account);
      return account;
    });

    expect(accounts).toHaveLength(23);
    expect(new Set(accounts.map((account) => account.surfaceId)).size).toBe(23);
    for (const account of accounts) {
      expect(account).toMatchObject({
        structuralAccountSchema: INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA,
        status: "structural-only",
        reasonCode: INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
        outputKinds: [],
      });
      expect(account.sourceRefs).toContain(
        "src/bin/ibex/runtime.rs#Runtime::start_inspector:armed-sink-guard",
      );
      expect(account.sourceRefs).toContain(
        "src/bin/ibex/engine/hermes.rs#HermesEngine::start_inspector:authorization-before-backend",
      );
      expect(account.sourceRefs).toContain(
        "src/bin/ibex/cdp/mod.rs#handle_connection",
      );
      expect(account.sourceRefs).toEqual(
        [...new Set(account.sourceRefs)].sort(),
      );
    }
  });

  test("publishes zero armed output rows and no unarmed response values", () => {
    expect(INSPECTOR_CDP_OUTPUT_CATALOG_BINDINGS).toEqual([]);
    const bindings = inspectorCdpStructuralAccountBindings(audit);
    expect(bindings.map(({ surfaceName }) => surfaceName)).toEqual(
      EXPECTED_SURFACES,
    );
    expect(
      bindings.every(
        (binding) =>
          binding.status === "structural-only" &&
          binding.reasonCode === INSPECTOR_CDP_STRUCTURAL_REASON_CODE &&
          binding.outputKinds.length === 0,
      ),
    ).toBe(true);

    const serialized = JSON.stringify({ audit, bindings });
    for (const forbidden of [
      "responseContract",
      "webSocketDebuggerUrl",
      "devtoolsFrontendUrl",
      "scriptSource",
      "exceptionDetails",
      "normalizedValue",
      "expectedValue",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  test("validates the standard catalog projection without output rows", () => {
    const accounts = cdpSurfaces.map((surface) => {
      const edge = edgesByObservedKey.get(surface.observedKey);
      return {
        surfaceId: edge.id,
        status: "structural-only",
        reasonCode: INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
        sourceRefs: [...audit.surfaces[surface.name].sourceRefs],
        outputKinds: [],
      };
    });
    const catalog = { surfaceAccounts: accounts, rows: [] };
    expect(
      validateInspectorCdpStructuralCatalog({
        catalog,
        coverage,
        sourceAudit: audit,
      }),
    ).toBe(true);

    const policyMutatedCoverage = structuredClone(coverage);
    for (const edge of policyMutatedCoverage.edges) {
      edge.classification = "test-policy-mutation";
      edge.cap = "test:mutated";
      edge.rationale = "test-only policy mutation";
      delete edge.effects;
    }
    expect(
      validateInspectorCdpStructuralCatalog({
        catalog,
        coverage: policyMutatedCoverage,
        sourceAudit: audit,
      }),
    ).toBe(true);

    const drifted = structuredClone(catalog);
    drifted.surfaceAccounts[0].status = "unresolved";
    expect(() =>
      validateInspectorCdpStructuralCatalog({
        catalog: drifted,
        coverage,
        sourceAudit: audit,
      }),
    ).toThrow(/inspector CDP catalog closure drift/u);
  });

  test("binds every CDP surface to the armed sink and listener token", () => {
    expect(audit).toMatchObject({
      reasonCode: "closed-before-inspector-dispatch",
      guardPhase: "armed-runtime-and-engine-start-sinks",
      dispatchBoundary:
        "cdp::start_server(&UnarmedInspectorAuthorization, ...)",
      sinkGuardMessage:
        "armed capability runtime closes inspector activation and configuration",
    });
    expect(audit.assertions.map(({ id }) => id)).toEqual([
      "runtime-armed-inspector-sink",
      "engine-armed-inspector-sink",
      "engine-mints-listener-authorization-after-guard",
      "listener-requires-unarmed-authorization",
      "connection-to-http-and-websocket",
    ]);
    expect(audit.diagnostics.assertions.map(({ id }) => id)).toEqual([
      "production-dispatch-guard",
      "guard-before-command-dispatch",
      "all-inspector-spellings-closed",
      "runtime-construction-revalidates",
      "file-inspector-after-runtime-construction",
      "session-inspector-after-runtime-construction",
      "worker-material-builds-the-guarded-runtime",
      "pre-clap-worker-uses-guarded-runtime",
    ]);
    expect(audit.diagnostics.literalCallSites).toEqual([
      {
        path: "src/bin/ibex/engine/hermes.rs",
        callee: "cdp::start_server(",
        count: 1,
      },
      {
        path: "src/bin/ibex/main.rs",
        callee: "runtime.start_inspector(",
        count: 2,
      },
      {
        path: "src/bin/ibex/runtime.rs",
        callee: "self.engine.start_inspector(",
        count: 1,
      },
    ]);
  });

  test("fails closed on guard, call-site, chain, and coverage drift", () => {
    const missingRuntimeSink = structuredClone(source);
    missingRuntimeSink.sourceFiles["src/bin/ibex/runtime.rs"] =
      missingRuntimeSink.sourceFiles["src/bin/ibex/runtime.rs"].replace(
        `        if self.host.armed_snapshot().is_some() {
            anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);
        }
`,
        "",
      );
    missingRuntimeSink.binaryRustSources["src/bin/ibex/runtime.rs"] =
      missingRuntimeSink.sourceFiles["src/bin/ibex/runtime.rs"];
    expect(() =>
      auditInspectorCdpStructuralClosure(missingRuntimeSink),
    ).toThrow(/runtime-armed-inspector-sink/u);

    const missingEngineSink = structuredClone(source);
    missingEngineSink.sourceFiles["src/bin/ibex/engine/hermes.rs"] =
      missingEngineSink.sourceFiles["src/bin/ibex/engine/hermes.rs"].replace(
        `        if self.armed_snapshot_digest.is_some() {
            anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);
        }
`,
        "",
      );
    missingEngineSink.binaryRustSources["src/bin/ibex/engine/hermes.rs"] =
      missingEngineSink.sourceFiles["src/bin/ibex/engine/hermes.rs"];
    expect(() => auditInspectorCdpStructuralClosure(missingEngineSink)).toThrow(
      /engine-armed-inspector-sink/u,
    );

    const missingListenerAuthorization = structuredClone(source);
    missingListenerAuthorization.sourceFiles["src/bin/ibex/cdp/mod.rs"] =
      missingListenerAuthorization.sourceFiles[
        "src/bin/ibex/cdp/mod.rs"
      ].replace(
        "    _authorization: &crate::engine::hermes::UnarmedInspectorAuthorization,\n",
        "",
      );
    missingListenerAuthorization.binaryRustSources["src/bin/ibex/cdp/mod.rs"] =
      missingListenerAuthorization.sourceFiles["src/bin/ibex/cdp/mod.rs"];
    expect(() =>
      auditInspectorCdpStructuralClosure(missingListenerAuthorization),
    ).toThrow(/listener-requires-unarmed-authorization/u);

    const missingGuard = structuredClone(source);
    missingGuard.sourceFiles["src/bin/ibex/runtime.rs"] =
      missingGuard.sourceFiles["src/bin/ibex/runtime.rs"].replace(
        "        || run_inspector\n",
        "",
      );
    missingGuard.binaryRustSources["src/bin/ibex/runtime.rs"] =
      missingGuard.sourceFiles["src/bin/ibex/runtime.rs"];
    expect(() => auditInspectorCdpStructuralClosure(missingGuard)).toThrow(
      /all-inspector-spellings-closed/u,
    );

    const bypass = structuredClone(source);
    bypass.binaryRustSources["src/bin/ibex/bypass.rs"] =
      'async fn bypass(runtime: &Runtime) { runtime.start_inspector("127.0.0.1", 0).await; }';
    expect(() => auditInspectorCdpStructuralClosure(bypass)).toThrow(
      /unexpected runtime\.start_inspector/u,
    );

    const brokenChain = structuredClone(source);
    brokenChain.sourceFiles["src/bin/ibex/engine/hermes.rs"] =
      brokenChain.sourceFiles["src/bin/ibex/engine/hermes.rs"].replace(
        "let server = cdp::start_server(&authorization, host, port, backend)?;",
        "let server = start_unreviewed_server(host, port, backend)?;",
      );
    brokenChain.binaryRustSources["src/bin/ibex/engine/hermes.rs"] =
      brokenChain.sourceFiles["src/bin/ibex/engine/hermes.rs"];
    expect(() => auditInspectorCdpStructuralClosure(brokenChain)).toThrow(
      /engine-mints-listener-authorization|cdp::start_server/u,
    );

    const surface = cdpSurfaces.find(
      (candidate) => candidate.name === "inspector.cdp-http:/json",
    );
    const wrongEdge = structuredClone(
      edgesByObservedKey.get(surface.observedKey),
    );
    wrongEdge.surface.name = "inspector.cdp-http:/json-drifted";
    expect(() =>
      authoredInspectorCdpStructuralAccount({
        surface,
        coverageEdge: wrongEdge,
        sourceAudit: audit,
      }),
    ).toThrow(/invalid inspector CDP structural account/u);
  });

  test("keeps alias and UFCS call scanning diagnostic rather than proof", () => {
    const alternateSpellings = structuredClone(source);
    alternateSpellings.binaryRustSources[
      "src/bin/ibex/alternate-inspector-spellings.rs"
    ] = String.raw`
use crate::runtime::Runtime as ArmedRuntime;
use crate::engine::Engine as InspectorEngine;
use crate::cdp::start_server as launch;
use crate::cdp as inspector_protocol;

async fn receiver_alias(runtime: &ArmedRuntime) {
    let alias = runtime;
    alias.start_inspector("127.0.0.1", 0).await.unwrap();
}

async fn runtime_ufcs(runtime: &ArmedRuntime) {
    ArmedRuntime::start_inspector(runtime, "127.0.0.1", 0)
        .await
        .unwrap();
}

async fn engine_ufcs(engine: &dyn InspectorEngine) {
    InspectorEngine::start_inspector(engine, "127.0.0.1", 0)
        .await
        .unwrap();
}

fn imported_listener_alias(authorization: &UnarmedInspectorAuthorization, backend: Backend) {
    launch(authorization, "127.0.0.1", 0, backend).unwrap();
    inspector_protocol::start_server(authorization, "127.0.0.1", 0, backend).unwrap();
}`;

    const alternateAudit =
      auditInspectorCdpStructuralClosure(alternateSpellings);
    expect(alternateAudit.proofSetDigest).toBe(audit.proofSetDigest);
    expect(alternateAudit.diagnostics.literalCallSites).toEqual(
      audit.diagnostics.literalCallSites,
    );
  });

  test("comments cannot fabricate a new armed CDP account", () => {
    const commented = structuredClone(source);
    commented.sourceFiles["src/bin/ibex/cdp/mod.rs"] +=
      '\n// "Runtime.fabricated" => { ctx.send_text("fake").await?; }\n';
    commented.binaryRustSources["src/bin/ibex/cdp/mod.rs"] =
      commented.sourceFiles["src/bin/ibex/cdp/mod.rs"];
    const commentedAudit = auditInspectorCdpStructuralClosure(commented);
    expect(Object.keys(commentedAudit.surfaces).sort()).toEqual(
      EXPECTED_SURFACES,
    );
  });
});
