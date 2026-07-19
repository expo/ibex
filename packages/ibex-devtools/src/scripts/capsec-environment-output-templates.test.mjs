import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createEnvProxy } from "../../../ibex-runtime-js/src/node/process.ts";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
  ENVIRONMENT_LEGACY_STRUCTURAL_REASON_CODE,
  ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA,
  ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA,
  ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA,
  ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD,
  ENVIRONMENT_PARAMETERIZED_REASON_CODE,
  LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
  auditCanonicalEnvironmentOutputSources,
  canonicalEnvironmentOutputContract,
  environmentParameterizedOutputCatalogBindings,
  environmentStructuralAccountBindings,
  instantiateAuthorizedEnvironmentOutputAccounts,
  instantiateEnvironmentOutputAccount,
  validateEnvironmentOutputAccount,
  validateEnvironmentOutputCatalog,
} from "./capsec-environment-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const g = globalThis;
const ORIGINAL_GLOBALS = Object.fromEntries(
  ["__exactGetEnv", "__exactGetAllEnv", "__exactSetEnv"].map((name) => [
    name,
    Object.getOwnPropertyDescriptor(g, name),
  ]),
);

const read = (relativePath) =>
  fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const sourceInputs = () => ({
  armedRuntimeSource: read("src/bin/ibex/runtime.rs"),
  builtinProcessSource: read("src/builtins/process.js"),
  compatibilityReaderSources: Object.fromEntries(
    [
      "packages/ibex-runtime-js/src/fetch/Headers.ts",
      "packages/ibex-runtime-js/src/fetch/Request.ts",
      "packages/ibex-runtime-js/src/fetch/Response.ts",
      "packages/ibex-runtime-js/src/fetch/body.ts",
      "packages/ibex-runtime-js/src/fetch/fetch.ts",
      "packages/ibex-runtime-js/src/streams/ReadableStream.ts",
    ].map((sourcePath) => [sourcePath, read(sourcePath)]),
  ),
  exactGlobalSource: read("src/engine/bootstrap/exact-global.js"),
  hostInputsSource: read("packages/ibex-runtime-js/src/core/host-inputs.ts"),
  hostEnvironmentAbiSource: read("src/host/abi.rs"),
  hostEnvironmentSource: read("src/host/mod.rs"),
  nativeAuthorizationSource: read("src/engine/hermes_runtime_internal.h"),
  nativeEnvironmentSource: read("src/engine/hermes_runtime.cc"),
  processSetupSource: read("src/engine/hermes_runtime_process_setup.cc"),
  processFacadeSource: read("packages/ibex-runtime-js/src/node/process.ts"),
  runtimeInstallSource: read("src/engine/hermes_runtime.cc"),
  sharedBootstrapSource: read("packages/ibex-runtime-js/src/bootstrap.ts"),
  snapshotFactorySource: read("src/bin/ibex/runtime.rs"),
  snapshotSchemaSource: read("capsec/schema/armed-snapshot.schema.json"),
});

function installGlobal(name, value) {
  Object.defineProperty(g, name, {
    configurable: true,
    writable: true,
    value,
  });
}

function restoreGlobal(name, descriptor) {
  if (descriptor) Object.defineProperty(g, name, descriptor);
  else delete g[name];
}

afterEach(() => {
  for (const [name, descriptor] of Object.entries(ORIGINAL_GLOBALS)) {
    restoreGlobal(name, descriptor);
  }
});

let audit;
let contract;
let coverage;
let surfaces;

beforeAll(async () => {
  audit = auditCanonicalEnvironmentOutputSources(sourceInputs());
  coverage = JSON.parse(read("capsec/registry/coverage-edges.json"));
  surfaces = (await discoverRepositorySurfaces(repoRoot)).surfaces;
  contract = canonicalEnvironmentOutputContract({
    coverageEdges: coverage.edges,
    sourceAudit: audit,
    surfaces,
  });
}, 30_000);

function environmentCatalogFixture() {
  const structural = environmentStructuralAccountBindings(audit)[0];
  const parameterized = environmentParameterizedOutputCatalogBindings(contract);
  const canonicalBinding = parameterized[0];
  return {
    surfaceAccounts: [
      {
        surfaceId: contract.legacyNativeFamily.surfaceId,
        status: structural.status,
        reasonCode: structural.reasonCode,
        sourceRefs: structural.sourceRefs,
        outputKinds: structural.outputKinds,
      },
      {
        surfaceId: contract.surfaceId,
        status: canonicalBinding.status,
        reasonCode: canonicalBinding.reasonCode,
        sourceRefs: canonicalBinding.sourceRefs,
        outputKinds: canonicalBinding.outputKinds,
      },
    ],
    rows: [],
    [ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD]: parameterized,
  };
}

describe("canonical environment output templates", () => {
  test("proves the empty-base, current-principal armed source chain", () => {
    expect(audit).toMatchObject({
      auditSchema: ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA,
      canonicalDynamicFamily: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
      legacyUnarmedDynamicFamily: LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
      proofs: {
        aliasesShareCanonicalObject: true,
        armedHostEnvironmentBypassed: true,
        armedLegacyEnvironmentUnreachable: true,
        armedSetterNativeOnly: true,
        builtinPreservesCanonicalIdentity: true,
        currentPrincipalOverlayIsolation: true,
        deniedReadBecomesAbsent: true,
        enumerationAuthorizesEveryExactName: true,
        exactNameReadWriteIndependent: true,
        explicitEmptySnapshotBase: true,
        fixedCompatibilityControlsCaptured: true,
        fixedCompatibilityFalseBlocksEnvironmentFallback: true,
        processEnvironmentDescriptorPinned: true,
        proxyHardeningMutationRefused: true,
        proxyMarkerPresent: true,
        requestedAndCommitAuthorized: true,
        typedPrincipalOverlayOccurrence: true,
      },
    });
    expect(contract).toMatchObject({
      contractSchema: ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA,
      accountKind: "parameterized-exact-principal-overlay-read",
      surfaceObservedKey: `native-op:${CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY}`,
      authorization: {
        independence: "read-does-not-imply-write-and-write-does-not-imply-read",
        read: {
          capability: "env:read",
          stages: ["requested", "commit"],
          target: "principal-overlay",
        },
        write: {
          capability: "env:write",
          stages: ["requested", "commit"],
          target: "principal-overlay",
        },
      },
      base: {
        armedSnapshot: "explicit-empty-array",
        hostFallback: false,
      },
      enumeration: {
        membership: "current-principal-overlay-only",
        authorization: "independent-env:read-per-exact-name",
      },
      mutation: {
        hostProcessMutation: false,
        capability: "env:write",
        deleteEffect: "current-principal-overlay-delete",
        nativeSetter: "armed-only",
        setEffect: "current-principal-overlay-string-write",
      },
      output: {
        channel: "exact-property-read-return",
        dispositionClaim: "none",
        valueVariants: ["string", "undefined"],
      },
      parameter: {
        accountSetSource: "authenticated-policy-exact-name-selectors",
        binding: "one-concrete-name-per-account",
        wildcardAllowed: false,
      },
      terminalSurfaces: {
        enumerationRead: {
          name: "__exactGetAllEnv",
          readSurface: 1,
          authorization: "nonempty-per-exact-name",
        },
        scalarRead: {
          name: "__exactGetEnv",
          readSurface: 0,
        },
        write: {
          name: "__exactSetEnv",
        },
      },
    });

    const names = new Set(surfaces.map(({ name }) => name));
    expect(names.has(CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY)).toBe(true);
    expect(names.has(LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY)).toBe(true);
    expect(
      [...names].filter((name) =>
        /^global:(?:Bun|Exact)\.env\.\[\[dynamic-table:call-result-/u.test(
          name,
        ),
      ),
    ).toEqual([]);
    expect(JSON.stringify(contract)).not.toMatch(
      /sample|fixture|broker-base/iu,
    );
  }, 30_000);

  test("instantiates one finite principal-overlay read account per exact name", () => {
    const names = ["EXACT_SECRET_2", "NODE_ENV", "PATH"];
    const accounts = instantiateAuthorizedEnvironmentOutputAccounts(
      contract,
      names,
    );

    expect(accounts.map(({ accountId }) => accountId)).toEqual([
      "principal-overlay-environment-read:EXACT_SECRET_2",
      "principal-overlay-environment-read:NODE_ENV",
      "principal-overlay-environment-read:PATH",
    ]);
    for (const [index, account] of accounts.entries()) {
      const name = names[index];
      expect(account).toMatchObject({
        accountSchema: ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA,
        evidenceMode: "parameterized-exact-occurrence",
        operation: {
          capability: "env:read",
          occurrence: {
            requested: {
              kind: "environment-name",
              name,
              target: "principal-overlay",
            },
            valueOrigin: "principal-overlay",
          },
          stages: ["requested", "commit"],
          terminalSurface: {
            name: "__exactGetEnv",
            surfaceId: contract.terminalSurfaces.scalarRead.surfaceId,
          },
        },
        output: {
          dispositionClaim: "none",
          valueVariants: ["string", "undefined"],
        },
      });
      expect(account.memberAliases.map(({ member }) => member)).toEqual([
        `global:process.env.${name}`,
        `global:Exact.env.${name}`,
        `global:Bun.env.${name}`,
      ]);
      expect(() =>
        validateEnvironmentOutputAccount(account, contract),
      ).not.toThrow();
    }

    for (const invalid of [
      "",
      "*",
      "PATH*",
      "path",
      "A=B",
      "A-B",
      "0PATH",
      null,
      {},
    ]) {
      expect(() =>
        instantiateEnvironmentOutputAccount(contract, invalid),
      ).toThrow(/invalid exact environment name/u);
    }
    expect(() =>
      instantiateAuthorizedEnvironmentOutputAccounts(contract, [
        "PATH",
        "NODE_ENV",
      ]),
    ).toThrow(/canonically sorted/u);
    expect(() =>
      instantiateAuthorizedEnvironmentOutputAccounts(contract, [
        "PATH",
        "PATH",
      ]),
    ).toThrow(/unique/u);
    expect(() =>
      instantiateAuthorizedEnvironmentOutputAccounts(contract, []),
    ).toThrow(/non-empty/u);
  });

  test("publishes a rowless legacy binding and a canonical parameterized catalog family", () => {
    expect(environmentStructuralAccountBindings(audit)).toEqual([
      expect.objectContaining({
        surfaceName: LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
        status: "structural-only",
        reasonCode: ENVIRONMENT_LEGACY_STRUCTURAL_REASON_CODE,
        outputKinds: [],
      }),
    ]);
    expect(environmentParameterizedOutputCatalogBindings(contract)).toEqual([
      expect.objectContaining({
        surfaceId: contract.surfaceId,
        surfaceName: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
        status: "output-bearing",
        reasonCode: ENVIRONMENT_PARAMETERIZED_REASON_CODE,
        outputKinds: ["exact-property-read-return"],
        terminalSurfaces: contract.terminalSurfaces,
        ordinaryCatalogRows: "forbidden",
      }),
    ]);

    const catalog = environmentCatalogFixture();
    expect(
      validateEnvironmentOutputCatalog({
        catalog,
        contract,
        coverage,
        sourceAudit: audit,
      }),
    ).toBe(true);

    const duplicateAccount = structuredClone(catalog);
    duplicateAccount.surfaceAccounts.push(
      structuredClone(duplicateAccount.surfaceAccounts[0]),
    );
    expect(() =>
      validateEnvironmentOutputCatalog({
        catalog: duplicateAccount,
        contract,
        coverage,
        sourceAudit: audit,
      }),
    ).toThrow(/duplicates surface account/u);

    const duplicateRows = structuredClone(catalog);
    const row = {
      key: {
        surfaceId: "surface.synthetic.environment",
        output: "[[return]]",
        alias: "synthetic",
        mode: "all",
        sourceKind: "native-op",
        returnVariant: "default",
        contextId: "javascript.package-property-read-loaded",
      },
    };
    duplicateRows.rows.push(row, structuredClone(row));
    expect(() =>
      validateEnvironmentOutputCatalog({
        catalog: duplicateRows,
        contract,
        coverage,
        sourceAudit: audit,
      }),
    ).toThrow(/duplicate key/u);

    const sampledCanonical = structuredClone(catalog);
    sampledCanonical.rows.push({
      key: {
        surfaceId: contract.surfaceId,
        output: "[[representative-read]]",
        alias: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
        mode: "sample",
        sourceKind: "native-op",
        returnVariant: "default",
        contextId: "javascript.package-property-read-loaded",
      },
    });
    expect(() =>
      validateEnvironmentOutputCatalog({
        catalog: sampledCanonical,
        contract,
        coverage,
        sourceAudit: audit,
      }),
    ).toThrow(/without ordinary catalog rows/u);

    const missingCanonical = structuredClone(catalog);
    delete missingCanonical[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD];
    expect(() =>
      validateEnvironmentOutputCatalog({
        catalog: missingCanonical,
        contract,
        coverage,
        sourceAudit: audit,
      }),
    ).toThrow(/binding is missing or drifted/u);
  });

  test("rejects empty-base, overlay, authorization, facade, and coverage source drift", () => {
    const inputs = sourceInputs();
    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        armedRuntimeSource: inputs.armedRuntimeSource.replace(
          "value: globalThis.Exact",
          "value: {}",
        ),
      }),
    ).toThrow(/runtime preload must install and pin Bun/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        snapshotSchemaSource: inputs.snapshotSchemaSource.replace(
          '"maxItems": 0',
          '"maxItems": 1',
        ),
      }),
    ).toThrow(/explicitly empty environmentBase/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        hostEnvironmentSource: inputs.hostEnvironmentSource.replace(
          "target: EnvironmentTarget::PrincipalOverlay",
          "target: EnvironmentTarget::BrokerBase",
        ),
      }),
    ).toThrow(/principal-overlay reads and writes|broker-base/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        hostEnvironmentAbiSource: inputs.hostEnvironmentAbiSource.replace(
          "read_surface: u32",
          "/* read terminal selector removed */",
        ),
      }),
    ).toThrow(/scalar and nonempty-enumeration edges/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeAuthorizationSource: inputs.nativeAuthorizationSource.replace(
          /(inline bool typedEnvironmentOverlayAccessAllowed\([\s\S]*?)for \(uint32_t stage = 0; stage <= 1; \+\+stage\)/u,
          "$1for (uint32_t stage = 0; stage == 0; ++stage)",
        ),
      }),
    ).toThrow(/both stages/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource.replace(
          "if (handle->armed) {\n    auto setEnvFn =",
          "if (false) {\n    auto setEnvFn =",
        ),
      }),
    ).toThrow(/native scalar environment write: source region unavailable/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource.replace(
          "authorizeTypedEnvironmentRead(runtime, key);",
          "getEnvValue(key);\n        authorizeTypedEnvironmentRead(runtime, key);",
        ),
      }),
    ).toThrow(/no host environment reader/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource.replace(
          "key, ExactEnvironmentOverlayAccess::EnumerationRead",
          "key, ExactEnvironmentOverlayAccess::ScalarRead",
        ),
      }),
    ).toThrow(/authorize every current-principal overlay name/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource.replace(
          '          return env;\n        }\n        if (!checkCapability("env:read:*"))',
          '          if (keys.empty()) return env;\n        }\n        if (!checkCapability("env:read:*"))',
        ),
      }),
    ).toThrow(/must return before the diagnostic environment gate/u);

    const diagnosticEnvironmentCall =
      "        populateDiagnosticProcessEnvironment(runtime, env);";
    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource
          .replace(`${diagnosticEnvironmentCall}\n`, "")
          .replace(
            "        facebook::jsi::Object env(runtime);",
            `        facebook::jsi::Object env(runtime);\n${diagnosticEnvironmentCall}`,
          ),
      }),
    ).toThrow(/authorize every current-principal overlay name|unarmed wildcard gate/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource.replace(
          '  rt.global().setProperty(rt, "__exactGetAllEnv", std::move(getAllEnvFn));',
          '  rt.global().setProperty(rt, "__exactGetAllEnv", std::move(getAllEnvFn));\n  GetEnvironmentStringsW();',
        ),
      }),
    ).toThrow(/must be confined to the guarded diagnostic helper/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource.replace(
          "LPWCH envBlock = GetEnvironmentStringsW();",
          "LPWCH envBlock = readDiagnosticWindowsEnvironment();",
        ),
      }),
    ).toThrow(/retain every platform host reader/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        processFacadeSource: inputs.processFacadeSource.replace(
          "if (prop === '__exactEnvProxy')",
          "if (false)",
        ),
      }),
    ).toThrow(/canonical proxy must preserve/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        builtinProcessSource: inputs.builtinProcessSource.replace(
          "!_rawEnv.__exactEnvProxy &&",
          "true &&",
        ),
      }),
    ).toThrow(/preserve a marked canonical/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        hostInputsSource: inputs.hostInputsSource.replace(
          'typeof (globalThis as { __exactSetEnv?: unknown }).__exactSetEnv ===\n    "function"',
          "false",
        ),
      }),
    ).toThrow(/captured once and fail closed/u);

    const headersPath = "packages/ibex-runtime-js/src/fetch/Headers.ts";
    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        compatibilityReaderSources: {
          ...inputs.compatibilityReaderSources,
          [headersPath]: inputs.compatibilityReaderSources[headersPath].replace(
            "bootstrapValue !== undefined ||\n    isBootstrapCompatibilityControlFixed(key)",
            "bootstrapValue !== undefined",
          ),
        },
      }),
    ).toThrow(/fixed false authoritative/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        sharedBootstrapSource: inputs.sharedBootstrapSource.replace(
          "value: exactProcess.env,\n      writable: false,\n      configurable: false",
          "value: exactProcess.env,\n      writable: true,\n      configurable: true",
        ),
      }),
    ).toThrow(/pin process\.env/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        exactGlobalSource: inputs.exactGlobalSource.replace(
          "configurable: !nativePrincipalEnvironmentOverlay",
          "configurable: true",
        ),
      }),
    ).toThrow(/resolve and pin/u);

    const policyDriftedCoverage = structuredClone(coverage.edges);
    for (const edge of policyDriftedCoverage) {
      edge.classification = "test-policy-mutation";
      edge.cap = "test:mutated";
      edge.rationale = "test-only policy mutation";
      delete edge.effects;
    }
    expect(
      canonicalEnvironmentOutputContract({
        coverageEdges: policyDriftedCoverage,
        sourceAudit: audit,
        surfaces,
      }),
    ).toEqual(contract);

    const driftedCoverage = structuredClone(coverage.edges);
    driftedCoverage.find(
      ({ surface }) => surface.name === CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
    ).surface.kind = "host-abi";
    expect(() =>
      canonicalEnvironmentOutputContract({
        coverageEdges: driftedCoverage,
        sourceAudit: audit,
        surfaces,
      }),
    ).toThrow(/canonical environment family identity drift/u);

    const driftedTerminalCoverage = structuredClone(coverage.edges);
    driftedTerminalCoverage.find(
      ({ surface }) => surface.name === "__exactSetEnv",
    ).surface.kind = "host-abi";
    expect(() =>
      canonicalEnvironmentOutputContract({
        coverageEdges: driftedTerminalCoverage,
        sourceAudit: audit,
        surfaces,
      }),
    ).toThrow(/write environment terminal identity drift/u);

    const driftedSurfaces = structuredClone(surfaces);
    driftedSurfaces
      .find(({ name }) => name === CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY)
      .metadata.principalEnvironmentOverlaySourceContract.nativeBridges.pop();
    expect(() =>
      canonicalEnvironmentOutputContract({
        coverageEdges: coverage.edges,
        sourceAudit: audit,
        surfaces: driftedSurfaces,
      }),
    ).toThrow(/principal-overlay environment inventory family/u);
  });

  test("keeps one proxy identity while isolating native overlays by current principal", () => {
    const hostEnvironmentThatMustRemainInvisible = {
      HOST_SECRET: "must-not-leak",
      PATH: "/host/private/bin",
    };
    const overlays = new Map();
    const readAuthority = new Map([
      ["alpha", new Set(["SHARED_NAME"])],
      ["beta", new Set(["SHARED_NAME"])],
    ]);
    const writeAuthority = new Map([
      ["alpha", new Set(["SHARED_NAME", "WRITE_ONLY"])],
      ["beta", new Set(["SHARED_NAME"])],
    ]);
    const decisions = [];
    let currentPrincipal = "alpha";

    installGlobal("__exactGetEnv", (name) => {
      decisions.push([currentPrincipal, "read", "requested", name]);
      decisions.push([currentPrincipal, "read", "commit", name]);
      if (!readAuthority.get(currentPrincipal)?.has(name)) {
        throw new Error("Permission denied: env:read authority required");
      }
      return overlays.get(currentPrincipal)?.get(name);
    });
    installGlobal("__exactSetEnv", (name, value) => {
      decisions.push([currentPrincipal, "write", "requested", name]);
      decisions.push([currentPrincipal, "write", "commit", name]);
      if (!writeAuthority.get(currentPrincipal)?.has(name)) {
        throw new Error("Permission denied: env:write authority required");
      }
      const overlay = overlays.get(currentPrincipal) ?? new Map();
      overlays.set(currentPrincipal, overlay);
      if (value === undefined) overlay.delete(name);
      else overlay.set(name, value);
    });
    installGlobal("__exactGetAllEnv", () => {
      const readable = readAuthority.get(currentPrincipal) ?? new Set();
      return Object.fromEntries(
        [...(overlays.get(currentPrincipal) ?? new Map())]
          .filter(([name]) => readable.has(name))
          .sort(([left], [right]) =>
            left < right ? -1 : left > right ? 1 : 0,
          ),
      );
    });

    const canonicalEnv = createEnvProxy();
    expect(canonicalEnv.__exactEnvProxy).toBe(true);
    expect(canonicalEnv.PATH).toBeUndefined();
    expect(canonicalEnv.HOST_SECRET).toBeUndefined();
    expect(Object.keys(canonicalEnv)).toEqual([]);

    canonicalEnv.SHARED_NAME = "alpha-value";
    canonicalEnv.WRITE_ONLY = 41;
    expect(canonicalEnv.SHARED_NAME).toBe("alpha-value");
    expect(canonicalEnv.WRITE_ONLY).toBeUndefined();
    expect(Object.keys(canonicalEnv)).toEqual(["SHARED_NAME"]);

    currentPrincipal = "beta";
    expect(canonicalEnv.SHARED_NAME).toBeUndefined();
    expect(Object.keys(canonicalEnv)).toEqual([]);
    canonicalEnv.SHARED_NAME = "beta-value";
    expect(canonicalEnv.SHARED_NAME).toBe("beta-value");

    currentPrincipal = "alpha";
    expect(canonicalEnv.SHARED_NAME).toBe("alpha-value");
    expect(canonicalEnv.toJSON()).toEqual({ SHARED_NAME: "alpha-value" });
    expect(JSON.stringify(canonicalEnv)).toBe('{"SHARED_NAME":"alpha-value"}');
    delete canonicalEnv.SHARED_NAME;
    expect(canonicalEnv.SHARED_NAME).toBeUndefined();

    currentPrincipal = "beta";
    expect(canonicalEnv.SHARED_NAME).toBe("beta-value");
    expect(() => {
      canonicalEnv.WRITE_ONLY = "denied-for-beta";
    }).toThrow(/env:write authority required/u);
    expect(hostEnvironmentThatMustRemainInvisible.HOST_SECRET).toBe(
      "must-not-leak",
    );

    expect(Reflect.preventExtensions(canonicalEnv)).toBe(false);
    expect(Object.isExtensible(canonicalEnv)).toBe(true);
    expect(Reflect.setPrototypeOf(canonicalEnv, null)).toBe(false);
    expect(Object.getPrototypeOf(canonicalEnv)).toBe(Object.prototype);
    expect(() => Object.freeze(canonicalEnv)).toThrow(TypeError);
    expect(() =>
      Reflect.set(canonicalEnv, Symbol("host-key"), "value"),
    ).toThrow(TypeError);

    expect(decisions).toContainEqual([
      "alpha",
      "write",
      "requested",
      "SHARED_NAME",
    ]);
    expect(decisions).toContainEqual([
      "alpha",
      "write",
      "commit",
      "SHARED_NAME",
    ]);
    expect(decisions).toContainEqual([
      "beta",
      "read",
      "requested",
      "SHARED_NAME",
    ]);
    expect(decisions).toContainEqual(["beta", "read", "commit", "SHARED_NAME"]);
  });
});
