import { beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  auditDebuggerNativeAliasClosure,
  authoredDebuggerNativeAliasStructuralAccount,
  DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA,
  DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
  DEBUGGER_NATIVE_ALIAS_SURFACES,
  debuggerNativeAliasStructuralAccountBindings,
  validateDebuggerNativeAliasStructuralCatalog,
} from "./capsec-debugger-native-alias-accounts.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const SOURCE_HERMES_PATH = "src/engine/hermes_runtime_debugger.cc";
const WINDOWS_PATH = "src/engine/hermes_runtime_platform_windows.cc";
const HERMES_RUST_PATH = "src/bin/ibex/engine/hermes.rs";
const CDP_RUST_PATH = "src/bin/ibex/cdp/mod.rs";
const RUNTIME_RUST_PATH = "src/bin/ibex/runtime.rs";
const REQUIRED_PATHS = [
  SOURCE_HERMES_PATH,
  WINDOWS_PATH,
  HERMES_RUST_PATH,
  CDP_RUST_PATH,
  RUNTIME_RUST_PATH,
];

const readText = (relativePath) =>
  fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
const readJson = (relativePath) => JSON.parse(readText(relativePath));

function binaryRustSources() {
  const binaryRoot = path.join(repoRoot, "src/bin/ibex");
  return Object.fromEntries(
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
}

function replaceExact(source, before, after, label) {
  const start = source.indexOf(before);
  if (start === -1 || source.indexOf(before, start + before.length) !== -1) {
    throw new Error(`${label}: expected one mutation target`);
  }
  return source.slice(0, start) + after + source.slice(start + before.length);
}

function replaceAfter(source, marker, before, after, label) {
  const markerIndex = source.indexOf(marker);
  if (markerIndex === -1) throw new Error(`${label}: missing marker`);
  const start = source.indexOf(before, markerIndex + marker.length);
  if (start === -1) throw new Error(`${label}: missing mutation target`);
  return source.slice(0, start) + after + source.slice(start + before.length);
}

function syntheticCatalog(sourceAudit) {
  const surfaceAccounts = [];
  const rows = [];
  for (const proof of Object.values(sourceAudit.surfaces)) {
    surfaceAccounts.push({
      surfaceId: proof.nativeSurfaceId,
      status: "structural-only",
      reasonCode: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
      sourceRefs: [...proof.sourceRefs],
      outputKinds: [],
    });
    surfaceAccounts.push(structuredClone(proof.companionCatalogAccount));
    rows.push(structuredClone(proof.companionCatalogRow));
  }
  return { surfaceAccounts, rows };
}

let sourceFiles;
let rustSources;
let surfaces;
let coverage;
let sourceAudit;

beforeAll(async () => {
  sourceFiles = Object.fromEntries(
    REQUIRED_PATHS.map((relativePath) => [
      relativePath,
      readText(relativePath),
    ]),
  );
  rustSources = binaryRustSources();
  surfaces = (await discoverRepositorySurfaces(repoRoot)).surfaces;
  coverage = readJson("capsec/registry/coverage-edges.json");
  sourceAudit = auditDebuggerNativeAliasClosure({
    sourceFiles,
    binaryRustSources: rustSources,
    surfaces,
    coverage,
  });
}, 30_000);

describe("source-bound debugger native alias accounts", () => {
  test("binds exactly six rowless native aliases to six output-bearing Host ABI returns", () => {
    expect(Object.keys(sourceAudit.surfaces)).toEqual(
      DEBUGGER_NATIVE_ALIAS_SURFACES,
    );
    expect(sourceAudit.structuralAccountSchema).toBe(
      DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA,
    );
    const bindings = debuggerNativeAliasStructuralAccountBindings(sourceAudit);
    expect(bindings).toHaveLength(6);
    expect(
      bindings.map((binding) => ({
        name: binding.surfaceName,
        status: binding.status,
        outputKinds: binding.outputKinds,
        dependency: binding.outputDependencies[0],
      })),
    ).toEqual(
      DEBUGGER_NATIVE_ALIAS_SURFACES.map((nativeName) => {
        const proof = sourceAudit.surfaces[nativeName];
        return {
          name: nativeName,
          status: "structural-only",
          outputKinds: [],
          dependency: {
            surfaceObservedKey: proof.hostObservedKey,
            selector: "[[return]]",
          },
        };
      }),
    );

    const byObservedKey = new Map(
      surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const edgeByObservedKey = new Map(
      coverage.edges.map((edge) => [
        `${edge.surface.kind}:${edge.surface.name}`,
        edge,
      ]),
    );
    const accounts = DEBUGGER_NATIVE_ALIAS_SURFACES.map((nativeName) => {
      const proof = sourceAudit.surfaces[nativeName];
      return authoredDebuggerNativeAliasStructuralAccount({
        surface: byObservedKey.get(proof.nativeObservedKey),
        coverageEdge: edgeByObservedKey.get(proof.nativeObservedKey),
        sourceAudit,
      });
    });
    expect(accounts).toHaveLength(6);
    expect(accounts.every((account) => account.outputKinds.length === 0)).toBe(
      true,
    );
    expect(
      new Set(
        accounts.map(
          (account) => account.outputDependencies[0].surfaceObservedKey,
        ),
      ).size,
    ).toBe(6);
  });

  test("accounts for source-Hermes enabled/disabled and Windows stubs", () => {
    for (const proof of Object.values(sourceAudit.surfaces)) {
      expect(proof.implementationBranches.map((branch) => branch.id)).toEqual([
        "source-hermes:debugger-disabled",
        "source-hermes:debugger-enabled",
        "windows-stub",
      ]);
      expect(
        proof.implementationBranches.every(
          (branch) =>
            branch.outputOwnerObservedKey === proof.hostObservedKey &&
            branch.proofDigest.startsWith("sha256-"),
        ),
      ).toBe(true);
    }
    expect(
      sourceAudit.surfaces["inspector.debugger-enable"]
        .implementationBranches[2].returnSentinel,
    ).toBe("0");
    expect(
      sourceAudit.surfaces["inspector.debugger-get-scripts"]
        .implementationBranches[2].returnSentinel,
    ).toBe("null");
    for (const nativeName of [
      "inspector.debugger-eval",
      "inspector.debugger-get-script-source",
      "inspector.debugger-next-event",
      "inspector.debugger-set-breakpoint",
    ]) {
      expect(
        sourceAudit.surfaces[nativeName].implementationBranches[2]
          .returnSentinel,
      ).toBe("null");
    }
  });

  test("derives membership independently of mutable coverage policy fields", () => {
    const mutatedCoverage = structuredClone(coverage);
    for (const edge of mutatedCoverage.edges) {
      edge.classification = "test-policy-mutation";
      edge.cap = "test:mutated";
      edge.rationale = "test-only policy mutation";
      delete edge.effects;
    }
    const mutatedAudit = auditDebuggerNativeAliasClosure({
      sourceFiles,
      binaryRustSources: rustSources,
      surfaces,
      coverage: mutatedCoverage,
    });
    expect(mutatedAudit).toEqual(sourceAudit);
    expect(
      validateDebuggerNativeAliasStructuralCatalog({
        catalog: syntheticCatalog(sourceAudit),
        coverage: mutatedCoverage,
        sourceAudit,
      }),
    ).toBe(true);
  });

  test("accepts only the exact structural/Host ABI catalog pair set", () => {
    const catalog = syntheticCatalog(sourceAudit);
    expect(
      validateDebuggerNativeAliasStructuralCatalog({
        catalog,
        coverage,
        sourceAudit,
      }),
    ).toBe(true);

    const missingCompanion = structuredClone(catalog);
    const missingId =
      sourceAudit.surfaces["inspector.debugger-eval"].hostSurfaceId;
    missingCompanion.surfaceAccounts = missingCompanion.surfaceAccounts.filter(
      (account) => account.surfaceId !== missingId,
    );
    expect(() =>
      validateDebuggerNativeAliasStructuralCatalog({
        catalog: missingCompanion,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/exact set/u);

    const unresolvedCompanion = structuredClone(catalog);
    unresolvedCompanion.surfaceAccounts.find(
      (account) => account.surfaceId === missingId,
    ).status = "unresolved";
    expect(() =>
      validateDebuggerNativeAliasStructuralCatalog({
        catalog: unresolvedCompanion,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/companion Host ABI account/u);

    const mismatchedRow = structuredClone(catalog);
    mismatchedRow.rows.find((row) => row.key.surfaceId === missingId).key.mode =
      "unarmed";
    expect(() =>
      validateDebuggerNativeAliasStructuralCatalog({
        catalog: mismatchedRow,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/companion Host ABI output row/u);

    const duplicateNativeOutput = structuredClone(catalog);
    const nativeProof = sourceAudit.surfaces["inspector.debugger-eval"];
    duplicateNativeOutput.rows.push({
      ...structuredClone(nativeProof.companionCatalogRow),
      key: {
        ...structuredClone(nativeProof.companionCatalogRow.key),
        surfaceId: nativeProof.nativeSurfaceId,
        sourceKind: "native-op",
      },
    });
    expect(() =>
      validateDebuggerNativeAliasStructuralCatalog({
        catalog: duplicateNativeOutput,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/exactly six companion rows/u);
  });

  test("preserves the first token after whitespace and rejects actual token loss", () => {
    const spacedSources = { ...sourceFiles };
    const spacedRust = { ...rustSources };
    spacedSources[RUNTIME_RUST_PATH] = replaceAfter(
      spacedSources[RUNTIME_RUST_PATH],
      "pub async fn start_inspector",
      "if self.host.armed_snapshot().is_some() {",
      "if    self.host.armed_snapshot().is_some() {",
      "spaced Runtime guard",
    );
    spacedRust[RUNTIME_RUST_PATH] = spacedSources[RUNTIME_RUST_PATH];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: spacedSources,
        binaryRustSources: spacedRust,
        surfaces,
        coverage,
      }),
    ).not.toThrow();

    const truncatedSources = { ...sourceFiles };
    const truncatedRust = { ...rustSources };
    truncatedSources[RUNTIME_RUST_PATH] = replaceAfter(
      truncatedSources[RUNTIME_RUST_PATH],
      "pub async fn start_inspector",
      "if self.host.armed_snapshot().is_some() {",
      "if elf.host.armed_snapshot().is_some() {",
      "truncated Runtime guard",
    );
    truncatedRust[RUNTIME_RUST_PATH] = truncatedSources[RUNTIME_RUST_PATH];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: truncatedSources,
        binaryRustSources: truncatedRust,
        surfaces,
        coverage,
      }),
    ).toThrow(/Runtime armed inspector sink/u);
  });

  test("rejects omitted or unreviewed source paths", () => {
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: {
          ...sourceFiles,
          "src/engine/unreviewed_debugger_alias.cc": "",
        },
        binaryRustSources: rustSources,
        surfaces,
        coverage,
      }),
    ).toThrow(/exact five-file source set/u);

    const omittedRust = { ...rustSources };
    delete omittedRust["src/bin/ibex/agent_logs.rs"];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles,
        binaryRustSources: omittedRust,
        surfaces,
        coverage,
      }),
    ).toThrow(/reviewed exact path set/u);

    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles,
        binaryRustSources: {
          ...rustSources,
          "src/bin/ibex/unreviewed_debugger_alias.rs": "",
        },
        surfaces,
        coverage,
      }),
    ).toThrow(/reviewed exact path set/u);
  });

  test("fails closed if the engine guard, private token, or call ownership drifts", () => {
    const guardSources = { ...sourceFiles };
    const guardRust = { ...rustSources };
    guardSources[HERMES_RUST_PATH] = replaceAfter(
      guardSources[HERMES_RUST_PATH],
      "fn unarmed_inspector_authorization(&self) -> Result<UnarmedInspectorAuthorization>",
      "if self.armed_snapshot_digest.is_some() {",
      "if false {",
      "armed engine guard",
    );
    guardRust[HERMES_RUST_PATH] = guardSources[HERMES_RUST_PATH];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: guardSources,
        binaryRustSources: guardRust,
        surfaces,
        coverage,
      }),
    ).toThrow(/armed inspector sink/u);

    const tokenSources = { ...sourceFiles };
    const tokenRust = { ...rustSources };
    tokenSources[CDP_RUST_PATH] = replaceExact(
      tokenSources[CDP_RUST_PATH],
      "_authorization: &crate::engine::hermes::UnarmedInspectorAuthorization,",
      "_authorization: &(),",
      "CDP authorization parameter",
    );
    tokenRust[CDP_RUST_PATH] = tokenSources[CDP_RUST_PATH];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: tokenSources,
        binaryRustSources: tokenRust,
        surfaces,
        coverage,
      }),
    ).toThrow(/CDP listener authorization/u);

    const escapedSources = { ...sourceFiles };
    const escapedRust = { ...rustSources };
    escapedSources[HERMES_RUST_PATH] += String.raw`
const DEBUGGER_ALIAS_ESCAPE: unsafe extern "C" fn(*mut HermesRuntimeOpaque) -> i32 =
    ex_hermes_debugger_enable;
`;
    escapedRust[HERMES_RUST_PATH] = escapedSources[HERMES_RUST_PATH];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: escapedSources,
        binaryRustSources: escapedRust,
        surfaces,
        coverage,
      }),
    ).toThrow(/one Rust declaration, one guarded production call/u);

    const backendSources = { ...sourceFiles };
    const backendRust = { ...rustSources };
    backendSources[HERMES_RUST_PATH] += String.raw`
fn debugger_backend_escape(
    runtime: Arc<SharedRuntime>,
    debugger_requested: Arc<AtomicBool>,
) -> HermesCdpBackend {
    HermesCdpBackend { runtime, debugger_requested }
}
`;
    backendRust[HERMES_RUST_PATH] = backendSources[HERMES_RUST_PATH];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: backendSources,
        binaryRustSources: backendRust,
        surfaces,
        coverage,
      }),
    ).toThrow(/backend type and literal sites/u);
  });

  test("fails closed if source-Hermes or Windows return branches drift", () => {
    const disabledSources = { ...sourceFiles };
    disabledSources[SOURCE_HERMES_PATH] = replaceAfter(
      disabledSources[SOURCE_HERMES_PATH],
      "ex_hermes_debugger_get_scripts",
      "return nullptr;",
      'return copyMallocString("[]");',
      "source-Hermes disabled return",
    );
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: disabledSources,
        binaryRustSources: rustSources,
        surfaces,
        coverage,
      }),
    ).toThrow(/source-Hermes branches/u);

    const windowsSources = { ...sourceFiles };
    windowsSources[WINDOWS_PATH] = replaceAfter(
      windowsSources[WINDOWS_PATH],
      "ex_hermes_debugger_get_scripts",
      "return nullptr;",
      'return copyMallocString("[]");',
      "Windows get-scripts sentinel",
    );
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles: windowsSources,
        binaryRustSources: rustSources,
        surfaces,
        coverage,
      }),
    ).toThrow(/Windows stub/u);
  });

  test("requires the exact six companion surfaces and their output contracts", () => {
    const missingCompanion = surfaces.filter(
      (surface) =>
        surface.observedKey !== "host-abi:ex_hermes_debugger_next_event",
    );
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles,
        binaryRustSources: rustSources,
        surfaces: missingCompanion,
        coverage,
      }),
    ).toThrow(/expected exact set/u);

    const mismatchedContracts = structuredClone(surfaces);
    const companion = mismatchedContracts.find(
      (surface) => surface.observedKey === "host-abi:ex_hermes_debugger_eval",
    );
    companion.metadata.outputContracts[0].outputChannels[0].selector =
      "return:json";
    companion.metadata.definitions[0].outputContract.outputChannels[0].selector =
      "return:json";
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles,
        binaryRustSources: rustSources,
        surfaces: mismatchedContracts,
        coverage,
      }),
    ).toThrow(/output contracts or target bindings drifted/u);

    const absentContracts = structuredClone(surfaces);
    absentContracts.find(
      (surface) =>
        surface.observedKey === "host-abi:ex_hermes_debugger_get_scripts",
    ).metadata.outputContracts = [];
    expect(() =>
      auditDebuggerNativeAliasClosure({
        sourceFiles,
        binaryRustSources: rustSources,
        surfaces: absentContracts,
        coverage,
      }),
    ).toThrow(/lacks two output contracts/u);
  });
});
