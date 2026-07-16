/**
 * Source-bound output accounts for the canonical process environment facade.
 *
 * Environment membership is intentionally not discovered by enumeration. One
 * account is instantiated for one normalized exact name, and Exact.env/Bun.env
 * are object-identity aliases of process.env rather than independent output
 * namespaces. Environment strings are opaque host data and may contain paths;
 * this module therefore makes no output-disposition claim.
 *
 * @ref LLP 0021#typed-resources-and-initial-vocabulary — environment authority
 * binds an exact name and broker/overlay target; wildcards are not valid names.
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * armed broker-base reads authorize requested and commit before disclosure,
 * while broker-base enumeration remains closed.
 */

export const ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA =
  "ibex/capsec-environment-output-source-audit/1";
export const ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA =
  "ibex/capsec-environment-output-contract/1";
export const ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA =
  "ibex/capsec-environment-output-account/1";

export const CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY =
  "global:process.env.[[dynamic-table:host-process-env-properties]]";
export const LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY =
  "global:process.env.[[dynamic-table:env-obj-properties]]";

const ENVIRONMENT_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/u;
const OPAQUE_ALIAS_FAMILY_PATTERN =
  /^global:(?:Bun|Exact)\.env\.\[\[dynamic-table:call-result-[a-f0-9]+-properties\]\]$/u;

const SOURCE_REFS = Object.freeze({
  armedSharedRuntimeGuard:
    "src/engine/hermes_runtime.cc#installGlobals:armed-shared-runtime-required",
  canonicalFacade:
    "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy",
  exactAliases: "src/engine/bootstrap/exact-global.js#Exact.env",
  nativeEnumeration: "src/engine/hermes_runtime.cc#__exactGetAllEnv",
  nativeScalarRead: "src/engine/hermes_runtime.cc#__exactGetEnv",
  sharedRuntimeAliases:
    "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:Exact.env",
});

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function requireSource(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label}: expected non-empty source text`);
  }
  return value;
}

function requireMatch(source, pattern, message) {
  if (!pattern.test(source)) throw new Error(message);
}

function sourceRegion(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error(`${label}: source region unavailable`);
  }
  return source.slice(start, end);
}

/**
 * Prove the source chain that makes process.env the only armed environment
 * namespace. The audit is intentionally structural about installation but
 * semantic about disclosure ordering and denial behavior.
 */
export function auditCanonicalEnvironmentOutputSources({
  exactGlobalSource,
  nativeEnvironmentSource,
  processFacadeSource,
  runtimeInstallSource,
  sharedBootstrapSource,
}) {
  const exactGlobal = requireSource(exactGlobalSource, "exact global");
  const nativeEnvironment = requireSource(
    nativeEnvironmentSource,
    "native environment",
  );
  const processFacade = requireSource(processFacadeSource, "process facade");
  const runtimeInstall = requireSource(runtimeInstallSource, "runtime install");
  const sharedBootstrap = requireSource(
    sharedBootstrapSource,
    "shared runtime bootstrap",
  );

  requireMatch(
    exactGlobal,
    /Object\.defineProperty\(E, 'env', \{[\s\S]*?get: function\(\) \{ return g\.process && g\.process\.env; \}[\s\S]*?\}\);/u,
    "Exact.env must resolve the current process.env object",
  );
  requireMatch(
    exactGlobal,
    /g\.Exact = E;\s*g\.Bun = E;/u,
    "legacy Exact and Bun facades must share one object",
  );
  if (
    /E\.env\s*=\s*\(function/u.test(exactGlobal) ||
    /__exactGet(?:All)?Env/u.test(exactGlobal)
  ) {
    throw new Error(
      "exact-global must not create or directly populate an environment proxy",
    );
  }

  requireMatch(
    sharedBootstrap,
    /g\.process = exactProcess;/u,
    "shared runtime must install the canonical Process instance",
  );
  requireMatch(
    sharedBootstrap,
    /Object\.defineProperty\(g\.Exact, 'env', \{[\s\S]*?get\(\) \{ return g\.process\?\.env; \}[\s\S]*?\}\);/u,
    "shared Exact.env must resolve the canonical process.env instance",
  );
  requireMatch(
    sharedBootstrap,
    /if \(bunCompatEnabled && !g\.Bun\) g\.Bun = g\.Exact;/u,
    "shared Bun facade must alias Exact when compatibility is enabled",
  );

  const envProxy = sourceRegion(
    processFacade,
    "export function createEnvProxy",
    "/**\n * Process object providing Node.js-like environment info.",
    "canonical environment proxy",
  );
  requireMatch(
    envProxy,
    /value = __exactGetEnv\(key\);/u,
    "canonical environment scalar reads must use __exactGetEnv(key)",
  );
  requireMatch(
    envProxy,
    /catch \(_error\) \{[\s\S]*?return undefined;[\s\S]*?\}/u,
    "canonical environment denial must become absence",
  );
  requireMatch(
    envProxy,
    /Object\.keys\(refreshNativeCache\(\)\)/u,
    "canonical enumeration must use the closed native enumeration bridge",
  );
  requireMatch(
    envProxy,
    /jsOverrides\.add\(key\);[\s\S]*?jsDeleted\.delete\(key\);/u,
    "canonical writes must retain JS overlay precedence",
  );
  requireMatch(
    envProxy,
    /jsOverrides\.delete\(key\);[\s\S]*?jsDeleted\.add\(key\);/u,
    "canonical deletes must retain native-value tombstones",
  );
  if (
    /__exactSetEnv|\bsetenv\s*\(|\bunsetenv\s*\(|env:(?:process-)?write/u.test(
      `${exactGlobal}\n${envProxy}\n${nativeEnvironment}`,
    )
  ) {
    throw new Error(
      "process environment facade must not expose a native setter or env:write path",
    );
  }
  requireMatch(
    processFacade,
    /readonly env: Record<string, string \| undefined> = createEnvProxy\(\);/u,
    "process.env must be the canonical createEnvProxy instance",
  );

  const scalarRead = sourceRegion(
    nativeEnvironment,
    "auto getEnvFn =",
    "auto getAllEnvFn =",
    "native scalar environment read",
  );
  const authorizeOffset = scalarRead.indexOf(
    "authorizeTypedEnvironmentRead(runtime, key);",
  );
  const discloseOffset = scalarRead.indexOf("auto value = getEnvValue(key);");
  if (
    authorizeOffset < 0 ||
    discloseOffset < 0 ||
    authorizeOffset >= discloseOffset
  ) {
    throw new Error(
      "native environment read must authorize the exact name before disclosure",
    );
  }

  const enumeration = sourceRegion(
    nativeEnvironment,
    "auto getAllEnvFn =",
    "auto setActiveModuleIdFn =",
    "native environment enumeration",
  );
  requireMatch(
    enumeration,
    /if \(handle->armed\) \{\s*return env;\s*\}/u,
    "armed native environment enumeration must return the empty result",
  );

  requireMatch(
    runtimeInstall,
    /if \(handle->armed && !sharedRuntimeInstalled\) \{[\s\S]*?Armed startup requires the capability-mediated shared runtime bundle[\s\S]*?\}/u,
    "armed startup must refuse the eager legacy process environment",
  );

  return deepFreeze({
    auditSchema: ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA,
    canonicalDynamicFamily: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
    legacyUnarmedDynamicFamily: LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
    namespaceRoots: [
      "global:process.env",
      "global:Exact.env",
      "global:Bun.env",
    ],
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
    sourceRefs: Object.values(SOURCE_REFS).sort(),
  });
}

function exactReadBranch(edge) {
  const branch = edge?.logicalBranches?.find(({ id }) => id === "read");
  const effect = branch?.effects?.[0];
  if (
    edge?.classification !== "effects" ||
    branch?.effects?.length !== 1 ||
    effect?.cap !== "env:read" ||
    effect?.selectorNormalizer !== "environment.name.selector.v1" ||
    effect?.occurrenceNormalizer !== "environment.name.occurrence.v1" ||
    JSON.stringify(effect?.stages) !== JSON.stringify(["requested", "commit"])
  ) {
    throw new Error(
      `${edge?.surface?.name ?? "environment family"}: exact-name read edge drift`,
    );
  }
  return branch;
}

/**
 * Bind the source proof to current inventory and the effect registry. Opaque
 * Exact/Bun call-result sentinels are forbidden: aliases do not get duplicate
 * output accounts.
 */
export function canonicalEnvironmentOutputContract({
  coverageEdges,
  sourceAudit,
  surfaces,
}) {
  if (
    sourceAudit?.auditSchema !== ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA ||
    sourceAudit?.canonicalDynamicFamily !== CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY
  ) {
    throw new Error("canonical environment source audit is missing or invalid");
  }
  if (!Array.isArray(surfaces) || !Array.isArray(coverageEdges)) {
    throw new Error(
      "environment contract requires surfaces and coverage edges",
    );
  }

  const opaqueAliases = surfaces.filter(({ name }) =>
    OPAQUE_ALIAS_FAMILY_PATTERN.test(name),
  );
  if (opaqueAliases.length !== 0) {
    throw new Error(
      `opaque Exact/Bun environment families remain: ${opaqueAliases
        .map(({ name }) => name)
        .sort()
        .join(", ")}`,
    );
  }

  const canonicalSurface = surfaces.find(
    ({ name }) => name === CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
  );
  const legacySurface = surfaces.find(
    ({ name }) => name === LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
  );
  if (!canonicalSurface || !legacySurface) {
    throw new Error(
      "canonical or guarded legacy environment family is missing",
    );
  }
  for (const alias of ["global:Exact.env", "global:Bun.env"]) {
    if (!surfaces.some(({ name }) => name === alias)) {
      throw new Error(`${alias}: namespace alias surface is missing`);
    }
  }

  const edge = coverageEdges.find(
    ({ surface }) => surface?.name === CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
  );
  exactReadBranch(edge);
  if (
    canonicalSurface.observedKey !==
      `native-op:${CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY}` ||
    edge?.surface?.kind !== "native-op"
  ) {
    throw new Error("canonical environment inventory/coverage binding drift");
  }

  return deepFreeze({
    contractSchema: ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA,
    accountKind: "parameterized-exact-environment-read",
    surfaceId: edge.id,
    surfaceObservedKey: canonicalSurface.observedKey,
    aliases: [
      { availability: "always", root: "global:process.env" },
      { availability: "always", root: "global:Exact.env" },
      {
        availability: "bun-compat-or-legacy",
        root: "global:Bun.env",
      },
    ],
    authorization: {
      capability: "env:read",
      stages: ["requested", "commit"],
      target: "broker-base",
    },
    enumeration: {
      brokerBase: "closed",
      nativeResult: "empty-object",
      visibleRemainder: "seeded-or-explicit-js-overlay-only",
    },
    legacyNativeFamily: {
      armedReachability: "refused-before-package-evaluation",
      observedKey: legacySurface.observedKey,
    },
    mutation: {
      brokerBaseMutation: false,
      capabilityClaim: "none",
      deleteEffect: "proxy-local-tombstone",
      nativeSetter: "absent",
      setEffect: "proxy-local-string-overlay",
    },
    output: {
      channel: "exact-property-read-return",
      dispositionClaim: "none",
      valueVariants: ["string", "undefined"],
    },
    parameter: {
      accountSetSource: "authenticated-policy-exact-name-selectors",
      binding: "one-concrete-name-per-account",
      maximumUtf8Bytes: 32768,
      name: "environmentName",
      normalizer: "environment.name.v1",
      pattern: ENVIRONMENT_NAME_PATTERN.source,
      wildcardAllowed: false,
    },
    proofMode: "source-bound-parameterized-occurrence",
    sourceRefs: sourceAudit.sourceRefs,
  });
}

function canonicalEnvironmentName(value) {
  if (
    typeof value !== "string" ||
    !ENVIRONMENT_NAME_PATTERN.test(value) ||
    Buffer.byteLength(value, "utf8") > 32768
  ) {
    throw new Error(`invalid exact environment name ${JSON.stringify(value)}`);
  }
  return value;
}

/** Instantiate one finite account without probing or enumerating the host. */
export function instantiateEnvironmentOutputAccount(contract, environmentName) {
  if (
    contract?.contractSchema !== ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA ||
    contract?.accountKind !== "parameterized-exact-environment-read" ||
    contract?.parameter?.wildcardAllowed !== false
  ) {
    throw new Error("invalid canonical environment output contract");
  }
  const name = canonicalEnvironmentName(environmentName);
  const memberAliases = contract.aliases.map(({ availability, root }) => ({
    availability,
    member: `${root}.${name}`,
  }));
  return deepFreeze({
    accountSchema: ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA,
    accountId: `broker-base-environment-read:${name}`,
    evidenceMode: "parameterized-exact-occurrence",
    memberAliases,
    operation: {
      capability: "env:read",
      occurrence: {
        kind: "environment-occurrence",
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
      channel: "exact-property-read-return",
      dispositionClaim: "none",
      valueVariants: ["string", "undefined"],
    },
    surfaceId: contract.surfaceId,
    surfaceObservedKey: contract.surfaceObservedKey,
  });
}

/**
 * Expand the finite exact-name set supplied by an authenticated policy. This
 * never consults process.env, ownKeys, or a representative fixture value.
 */
export function instantiateAuthorizedEnvironmentOutputAccounts(
  contract,
  authorizedNames,
) {
  if (!Array.isArray(authorizedNames) || authorizedNames.length === 0) {
    throw new Error("authorized environment account set must be non-empty");
  }
  const names = authorizedNames.map(canonicalEnvironmentName);
  const canonicalNames = [...new Set(names)].sort();
  if (JSON.stringify(names) !== JSON.stringify(canonicalNames)) {
    throw new Error(
      "authorized environment names must be unique and canonically sorted",
    );
  }
  return Object.freeze(
    canonicalNames.map((name) =>
      instantiateEnvironmentOutputAccount(contract, name),
    ),
  );
}

export function validateEnvironmentOutputAccount(account, contract) {
  if (
    account?.accountSchema !== ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA ||
    account?.surfaceId !== contract?.surfaceId ||
    account?.surfaceObservedKey !== contract?.surfaceObservedKey ||
    account?.evidenceMode !== "parameterized-exact-occurrence" ||
    account?.operation?.capability !== "env:read" ||
    account?.operation?.occurrence?.requested?.target !== "broker-base" ||
    account?.output?.dispositionClaim !== "none" ||
    JSON.stringify(account?.output?.valueVariants) !==
      JSON.stringify(["string", "undefined"])
  ) {
    throw new Error("invalid environment output account");
  }
  const name = canonicalEnvironmentName(
    account.operation.occurrence.requested.name,
  );
  const expected = instantiateEnvironmentOutputAccount(contract, name);
  if (JSON.stringify(account) !== JSON.stringify(expected)) {
    throw new Error("environment output account binding drift");
  }
  return account;
}
