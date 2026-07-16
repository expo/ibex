import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { createEnvProxy } from "../../../ibex-runtime-js/src/node/process.ts";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
  ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA,
  ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA,
  ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA,
  LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
  auditCanonicalEnvironmentOutputSources,
  canonicalEnvironmentOutputContract,
  instantiateAuthorizedEnvironmentOutputAccounts,
  instantiateEnvironmentOutputAccount,
  validateEnvironmentOutputAccount,
} from "./capsec-environment-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const g = globalThis;
const originalGetEnv = Object.getOwnPropertyDescriptor(g, "__exactGetEnv");
const originalGetAllEnv = Object.getOwnPropertyDescriptor(
  g,
  "__exactGetAllEnv",
);

const read = (relativePath) =>
  fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const sourceInputs = () => ({
  exactGlobalSource: read("src/engine/bootstrap/exact-global.js"),
  nativeEnvironmentSource: read("src/engine/hermes_runtime.cc"),
  processFacadeSource: read("packages/ibex-runtime-js/src/node/process.ts"),
  runtimeInstallSource: read("src/engine/hermes_runtime.cc"),
  sharedBootstrapSource: read("packages/ibex-runtime-js/src/bootstrap.ts"),
});

function restoreGlobal(name, descriptor) {
  if (descriptor) Object.defineProperty(g, name, descriptor);
  else delete g[name];
}

afterEach(() => {
  restoreGlobal("__exactGetEnv", originalGetEnv);
  restoreGlobal("__exactGetAllEnv", originalGetAllEnv);
});

let audit;
let contract;
let coverageEdges;
let surfaces;

beforeAll(async () => {
  audit = auditCanonicalEnvironmentOutputSources(sourceInputs());
  coverageEdges = JSON.parse(read("capsec/registry/coverage-edges.json")).edges;
  surfaces = (await discoverRepositorySurfaces(repoRoot)).surfaces;
  contract = canonicalEnvironmentOutputContract({
    coverageEdges,
    sourceAudit: audit,
    surfaces,
  });
}, 30_000);

describe("canonical environment output templates", () => {
  test("consolidates Exact.env and Bun.env into the canonical process.env family", () => {
    expect(audit).toMatchObject({
      auditSchema: ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA,
      canonicalDynamicFamily: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
      legacyUnarmedDynamicFamily: LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
      proofs: {
        aliasesShareCanonicalObject: true,
        armedBrokerEnumerationClosed: true,
        armedLegacyEnvironmentUnreachable: true,
        deniedBrokerReadBecomesAbsent: true,
        exactNameAuthorizationPrecedesDisclosure: true,
        localOverlayNeverCallsNativeSetter: true,
        localOverlayNeverMutatesBrokerBase: true,
        localOverlayWritesShareCanonicalObject: true,
      },
    });
    expect(contract).toMatchObject({
      contractSchema: ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA,
      accountKind: "parameterized-exact-environment-read",
      surfaceObservedKey: `native-op:${CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY}`,
      authorization: {
        capability: "env:read",
        stages: ["requested", "commit"],
        target: "broker-base",
      },
      enumeration: {
        brokerBase: "closed",
        nativeResult: "empty-object",
      },
      output: {
        channel: "exact-property-read-return",
        dispositionClaim: "none",
        valueVariants: ["string", "undefined"],
      },
      mutation: {
        brokerBaseMutation: false,
        capabilityClaim: "none",
        deleteEffect: "proxy-local-tombstone",
        nativeSetter: "absent",
        setEffect: "proxy-local-string-overlay",
      },
      parameter: {
        accountSetSource: "authenticated-policy-exact-name-selectors",
        binding: "one-concrete-name-per-account",
        wildcardAllowed: false,
      },
      proofMode: "source-bound-parameterized-occurrence",
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
    expect(JSON.stringify(contract)).not.toMatch(/sample|fixture/iu);
  }, 30_000);

  test("instantiates one finite account per exact authorized name", () => {
    const names = ["EXACT_SECRET_2", "NODE_ENV", "PATH"];
    const accounts = instantiateAuthorizedEnvironmentOutputAccounts(
      contract,
      names,
    );

    expect(accounts.map(({ accountId }) => accountId)).toEqual([
      "broker-base-environment-read:EXACT_SECRET_2",
      "broker-base-environment-read:NODE_ENV",
      "broker-base-environment-read:PATH",
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
              target: "broker-base",
            },
            valueOrigin: "broker-base",
          },
          stages: ["requested", "commit"],
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

  test("rejects alias, armed-guard, authorization-order, and coverage drift", () => {
    const inputs = sourceInputs();
    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        exactGlobalSource: inputs.exactGlobalSource.replace(
          "get: function() { return g.process && g.process.env; }",
          "E.env = (function() { return new Proxy({}, {}); })();",
        ),
      }),
    ).toThrow(/resolve the current process\.env object|must not create/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        runtimeInstallSource: inputs.runtimeInstallSource.replace(
          "if (handle->armed && !sharedRuntimeInstalled)",
          "if (false)",
        ),
      }),
    ).toThrow(/armed startup must refuse/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        nativeEnvironmentSource: inputs.nativeEnvironmentSource
          .replace(
            "authorizeTypedEnvironmentRead(runtime, key);",
            "/* authorization moved after disclosure */",
          )
          .replace(
            "auto value = getEnvValue(key);",
            "auto value = getEnvValue(key);\n        authorizeTypedEnvironmentRead(runtime, key);",
          ),
      }),
    ).toThrow(/authorize the exact name before disclosure/u);

    expect(() =>
      auditCanonicalEnvironmentOutputSources({
        ...inputs,
        processFacadeSource: inputs.processFacadeSource.replace(
          "target[key] = normalized;",
          "__exactSetEnv(key, normalized);\n      target[key] = normalized;",
        ),
      }),
    ).toThrow(/must not expose a native setter or env:write path/u);

    expect(() =>
      canonicalEnvironmentOutputContract({
        coverageEdges,
        sourceAudit: audit,
        surfaces: [
          ...surfaces,
          {
            kind: "native-op",
            name: "global:Exact.env.[[dynamic-table:call-result-deadbeef-properties]]",
          },
        ],
      }),
    ).toThrow(/opaque Exact\/Bun environment families remain/u);

    const driftedCoverage = structuredClone(coverageEdges);
    driftedCoverage.find(
      ({ surface }) => surface.name === CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
    ).classification = "closed";
    expect(() =>
      canonicalEnvironmentOutputContract({
        coverageEdges: driftedCoverage,
        sourceAudit: audit,
        surfaces,
      }),
    ).toThrow(/exact-name read edge drift/u);
  });

  test("shares production get/set/delete semantics and closes denied enumeration", () => {
    const broker = {
      ALLOWED_SECRET: "host-value",
      DENIED_SECRET: "must-not-leak",
      PATH: "/host/private/bin",
    };
    const authorized = new Set(["ALLOWED_SECRET"]);
    const scalarReads = [];
    let enumerationReads = 0;
    g.__exactGetEnv = (name) => {
      scalarReads.push(name);
      if (!authorized.has(name)) {
        throw new Error("Permission denied: env:read authority required");
      }
      return broker[name];
    };
    g.__exactGetAllEnv = () => {
      enumerationReads += 1;
      return {};
    };

    const canonicalEnv = createEnvProxy();
    const sandbox = { process: { env: canonicalEnv } };
    vm.runInNewContext(read("src/engine/bootstrap/exact-global.js"), sandbox, {
      filename: "<exact-global-environment-alias-test>",
    });

    expect(sandbox.Exact).toBe(sandbox.Bun);
    expect(sandbox.Exact.env).toBe(canonicalEnv);
    expect(sandbox.Bun.env).toBe(canonicalEnv);
    expect(sandbox.process.env).toBe(canonicalEnv);

    expect(sandbox.Exact.env.ALLOWED_SECRET).toBe("host-value");
    expect(sandbox.Bun.env.DENIED_SECRET).toBeUndefined();
    expect("DENIED_SECRET" in sandbox.Exact.env).toBe(false);
    expect(
      Object.getOwnPropertyDescriptor(sandbox.Bun.env, "DENIED_SECRET"),
    ).toBeUndefined();

    const initialKeys = Object.keys(sandbox.Exact.env);
    expect(initialKeys).toEqual(["NODE_ENV"]);
    expect(initialKeys).not.toContain("PATH");
    expect(initialKeys).not.toContain("DENIED_SECRET");
    expect(sandbox.Bun.env.toJSON()).toEqual({ NODE_ENV: "development" });
    expect(JSON.stringify(sandbox.Exact.env)).toBe(
      '{"NODE_ENV":"development"}',
    );
    expect(JSON.stringify(sandbox.Exact.env)).not.toContain("must-not-leak");
    expect(enumerationReads).toBeGreaterThanOrEqual(3);

    sandbox.Bun.env.ALLOWED_SECRET = 41;
    expect(sandbox.process.env.ALLOWED_SECRET).toBe("41");
    expect(sandbox.Exact.env.ALLOWED_SECRET).toBe("41");
    expect(broker.ALLOWED_SECRET).toBe("host-value");
    expect(Object.keys(sandbox.process.env)).toContain("ALLOWED_SECRET");
    expect(sandbox.Exact.env.toJSON().ALLOWED_SECRET).toBe("41");

    delete sandbox.Exact.env.ALLOWED_SECRET;
    expect(sandbox.process.env.ALLOWED_SECRET).toBeUndefined();
    expect("ALLOWED_SECRET" in sandbox.Bun.env).toBe(false);
    expect(Object.keys(sandbox.Exact.env)).not.toContain("ALLOWED_SECRET");

    sandbox.Exact.env.DENIED_SECRET = "local-overlay";
    expect(sandbox.process.env.DENIED_SECRET).toBe("local-overlay");
    expect(broker.DENIED_SECRET).toBe("must-not-leak");
    delete sandbox.Bun.env.DENIED_SECRET;
    expect(sandbox.Exact.env.DENIED_SECRET).toBeUndefined();
    expect(JSON.stringify(sandbox.process.env)).not.toContain("must-not-leak");

    expect(() =>
      Reflect.set(sandbox.Exact.env, Symbol("host-key"), "value"),
    ).toThrow(TypeError);
    expect(scalarReads).toContain("ALLOWED_SECRET");
    expect(scalarReads).toContain("DENIED_SECRET");
  });
});
