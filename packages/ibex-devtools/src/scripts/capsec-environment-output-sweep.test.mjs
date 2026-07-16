import { describe, expect, test } from "bun:test";
import {
  ENVIRONMENT_OUTPUT_SWEEP_EXECUTOR_RESULT_SCHEMA,
  ENVIRONMENT_OUTPUT_SWEEP_NAMES,
  ENVIRONMENT_PARAMETERIZED_CATALOG_BINDING_SCHEMA,
  buildEnvironmentOutputSweepBindings,
  buildEnvironmentOutputSweepObservations,
  environmentOutputSweepAuthoritySelectors,
  validateEnvironmentOutputSweepBindings,
  validateEnvironmentOutputSweepObservations,
} from "./capsec-environment-output-templates.mjs";
import { validateOutputShapeCatalogAccounts } from "./capsec-output-dispositions.mjs";

const catalogBindings = [
  {
    bindingSchema: ENVIRONMENT_PARAMETERIZED_CATALOG_BINDING_SCHEMA,
    surfaceId: "surface.global.process.env.dynamic.table",
    surfaceName:
      "global:process.env.[[dynamic-table:principal-environment-overlay-properties]]",
    status: "output-bearing",
    reasonCode: "parameterized-exact-principal-overlay-read",
    sourceRefs: ["fixture#process-env"],
    outputKinds: ["exact-property-read-return"],
    accountSchema: "ibex/capsec-environment-output-account/1",
    accountSetSource: "authenticated-policy-exact-name-selectors",
    binding: "one-concrete-name-per-account",
    terminalSurfaces: {
      enumerationRead: {
        name: "__exactGetAllEnv",
        readSurface: 1,
        surfaceId: "surface.native.get.all.env",
        authorization: "nonempty-per-exact-name",
      },
      scalarRead: {
        name: "__exactGetEnv",
        readSurface: 0,
        surfaceId: "surface.native.get.env",
      },
      write: {
        name: "__exactSetEnv",
        surfaceId: "surface.native.set.env",
      },
    },
    ordinaryCatalogRows: "forbidden",
  },
];

const executorIdentity = Object.freeze({
  executor: "ibex-public-surface-harness/output-shape-sweep-v3",
  loadedEngineBinaryDigest: `sha256-${"E".repeat(43)}`,
});
const semanticIdentity = Object.freeze({
  profile: "ibex/capsec/1",
  semanticCore: "capsec/semantics/1",
  vocabDigest: `sha256-${"A".repeat(43)}`,
  registryDigest: `sha256-${"B".repeat(43)}`,
  policyDigest: `sha256-${"C".repeat(43)}`,
  armedSnapshotDigest: `sha256-${"D".repeat(43)}`,
});
const rootPrincipal = Object.freeze({
  kind: "root",
  identity: "project-root",
});

function floorSourceId(binding, account, capability) {
  const selectors = binding.accounts
    .flatMap((candidate) => [
      candidate.readSelector,
      candidate.writeSetupSelector,
    ])
    .sort((left, right) => {
      const leftKey = `${left.cap}\0${left.resource.name}`;
      const rightKey = `${right.cap}\0${right.resource.name}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
  const index = selectors.findIndex(
    (selector) =>
      selector.cap === capability &&
      selector.resource.name === account.environmentName,
  );
  if (index < 0) throw new Error("fixture selector lacks a floor source ID");
  return `principal.000000.floor.${String(index).padStart(6, "0")}`;
}

function decision(binding, account, phase, stage, route = "primary") {
  const primary =
    route === "scalar"
      ? {
          cap: "env:read",
          operation: "environment-read",
          surfaceId: binding.terminalSurfaces.scalarRead.surfaceId,
        }
      : phase === "write-setup"
      ? {
          cap: "env:write",
          operation: "environment-write",
          surfaceId: binding.terminalSurfaces.write.surfaceId,
        }
      : phase === "enumeration"
        ? {
            cap: "env:read",
            operation: "environment-enumerate",
            surfaceId: binding.terminalSurfaces.enumerationRead.surfaceId,
          }
        : {
            cap: "env:read",
            operation: "environment-read",
            surfaceId: binding.terminalSurfaces.scalarRead.surfaceId,
          };
  const operationId = `${primary.operation}:0:${JSON.stringify({
    kind: "environment-name",
    target: "principal-overlay",
    name: account.environmentName,
  })}`;
  return {
    terminalBranchId: `output-shape-environment:${binding.sweepBindingDigest}:${phase}`,
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId,
      atomicityGroup: `${primary.surfaceId}.decision`,
      combination: "conjunction",
      context: {
        stage,
        actor: structuredClone(rootPrincipal),
        constrainedPrincipals: [structuredClone(rootPrincipal)],
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: primary.cap,
          effectOwner: structuredClone(rootPrincipal),
          resource: {
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name: account.environmentName,
            },
            valueOrigin: "principal-overlay",
          },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: primary.surfaceId,
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: {
      identity: structuredClone(semanticIdentity),
      generations: { negative: 0, dynamic: 0, handle: 0 },
      operationId,
      stage,
      actor: structuredClone(rootPrincipal),
      effectOwners: [structuredClone(rootPrincipal)],
      constrainedPrincipals: [structuredClone(rootPrincipal)],
      outcome: "allow",
      evidence: [
        {
          effectIndex: 0,
          principal: structuredClone(rootPrincipal),
          stratum: "static-floor",
          reason: "static-floor",
          sourceId: floorSourceId(binding, account, primary.cap),
        },
      ],
    },
  };
}

function executorResults(bindings) {
  return bindings.map((binding) => ({
    environmentOutputExecutorResultSchema:
      ENVIRONMENT_OUTPUT_SWEEP_EXECUTOR_RESULT_SCHEMA,
    executor: executorIdentity.executor,
    loadedEngineBinaryDigest: executorIdentity.loadedEngineBinaryDigest,
    surfaceId: binding.surfaceId,
    sweepBindingDigest: binding.sweepBindingDigest,
    accounts: binding.accounts.map((account, index) => ({
      accountId: account.accountId,
      environmentName: account.environmentName,
      scalarBefore: { valueShape: "undefined", value: null },
      scalarAfter: { valueShape: "string", value: `armed-value-${index}` },
      enumerated: { valueShape: "string", value: `armed-value-${index}` },
    })),
    enumerationNames: binding.accounts.map(
      ({ environmentName }) => environmentName,
    ),
    facadeAliases: { bun: true, exact: true },
    sealedRawBridges: {
      enumeration: "undefined",
      scalar: "undefined",
      write: "undefined",
    },
    hostEnvironmentCanary: {
      fixedNamesSeeded: true,
      scalarBeforeHidden: true,
      unchangedAfterOverlayWrites: true,
    },
    phases: binding.phases.map((phase) => ({
      phase,
      legacyObservationCount: 0,
      typedDecisions: binding.accounts.flatMap((account) => {
        const decisions = [
          decision(binding, account, phase, "requested"),
          decision(binding, account, phase, "commit"),
        ];
        if (phase === "enumeration") {
          for (let occurrence = 0; occurrence < 3; occurrence += 1) {
            decisions.push(
              decision(binding, account, phase, "requested", "scalar"),
              decision(binding, account, phase, "commit", "scalar"),
            );
          }
        }
        return decisions;
      }),
    })),
  }));
}

describe("finite environment output sweep evidence", () => {
  test("authors exact authenticated selectors and seals scalar/enumeration observations", () => {
    const bindings = buildEnvironmentOutputSweepBindings(catalogBindings);
    expect(() =>
      validateEnvironmentOutputSweepBindings(bindings, catalogBindings),
    ).not.toThrow();
    expect(
      bindings[0].accounts.map(({ environmentName }) => environmentName),
    ).toEqual(ENVIRONMENT_OUTPUT_SWEEP_NAMES);
    expect(environmentOutputSweepAuthoritySelectors(bindings)).toHaveLength(4);

    const observations = buildEnvironmentOutputSweepObservations(
      bindings,
      executorResults(bindings),
      executorIdentity,
    );
    expect(() =>
      validateEnvironmentOutputSweepObservations(
        bindings,
        observations,
        executorIdentity,
      ),
    ).not.toThrow();
    expect(observations[0]).toMatchObject({
      surfaceId: catalogBindings[0].surfaceId,
      probeKind: "loaded-engine-parameterized-environment",
      accounts: [
        {
          scalarBeforeShape: "undefined",
          scalarAfterShape: "string",
          enumerationShape: "string",
        },
        {
          scalarBeforeShape: "undefined",
          scalarAfterShape: "string",
          enumerationShape: "string",
        },
      ],
    });
    expect(JSON.stringify(observations)).not.toContain("armed-value-");
    expect(observations[0]).toMatchObject({
      executor: executorIdentity.executor,
      loadedEngineBinaryDigest: executorIdentity.loadedEngineBinaryDigest,
      hostEnvironmentCanary: {
        fixedNamesSeeded: true,
        scalarBeforeHidden: true,
        unchangedAfterOverlayWrites: true,
      },
    });
    expect(
      validateOutputShapeCatalogAccounts({
        surfaceAccounts: [
          {
            surfaceId: catalogBindings[0].surfaceId,
            status: catalogBindings[0].status,
            reasonCode: catalogBindings[0].reasonCode,
            sourceRefs: catalogBindings[0].sourceRefs,
            outputKinds: catalogBindings[0].outputKinds,
          },
        ],
        rows: [],
        parameterizedOutputBindings: catalogBindings,
        parameterizedOutputEvidence: observations,
        promotionStatus: "verified",
      }),
    ).toEqual({
      "output-bearing": 1,
      "structural-only": 0,
      unresolved: 0,
    });
  });

  test("fails closed on selector, phase, terminal, legacy, and value drift", () => {
    const bindings = buildEnvironmentOutputSweepBindings(catalogBindings);
    const driftedBinding = structuredClone(bindings);
    driftedBinding[0].accounts[0].readSelector.resource.name = "HOST_INFERRED";
    expect(() =>
      validateEnvironmentOutputSweepBindings(driftedBinding),
    ).toThrow(/binding|selector/u);

    for (const mutate of [
      (results) => results[0].phases.pop(),
      (results) => {
        results[0].phases[0].legacyObservationCount = 1;
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].gates[0].coverageEdgeId =
          "surface.native.wrong";
      },
      (results) => {
        results[0].accounts[0].enumerated.value = "different";
      },
      (results) => {
        results[0].phases
          .find(({ phase }) => phase === "enumeration")
          .typedDecisions.pop();
      },
      (results) => {
        const enumeration = results[0].phases.find(
          ({ phase }) => phase === "enumeration",
        );
        enumeration.typedDecisions.push(
          structuredClone(enumeration.typedDecisions.at(-1)),
        );
      },
    ]) {
      const results = executorResults(bindings);
      mutate(results);
      expect(() =>
        buildEnvironmentOutputSweepObservations(
          bindings,
          results,
          executorIdentity,
        ),
      ).toThrow();
    }
  });

  test("rejects incomplete, branchless, cross-executor, and secret-bearing decision envelopes", () => {
    const bindings = buildEnvironmentOutputSweepBindings(catalogBindings);

    const incomplete = executorResults(bindings);
    incomplete[0].phases[0].typedDecisions[0] = {
      decisionSet: {
        operationId: "environment-read:synthetic",
        context: { stage: "requested" },
        effects: [],
      },
      gates: [],
      evidence: { outcome: "allow" },
    };
    expect(() =>
      buildEnvironmentOutputSweepObservations(
        bindings,
        incomplete,
        executorIdentity,
      ),
    ).toThrow(/unexpected fields|executor branch/u);

    const wrongBranch = executorResults(bindings);
    wrongBranch[0].phases[0].typedDecisions[0].terminalBranchId =
      "output-shape-environment:other:scalar-before";
    expect(() =>
      buildEnvironmentOutputSweepObservations(
        bindings,
        wrongBranch,
        executorIdentity,
      ),
    ).toThrow(/executor branch/u);

    const wrongExecutor = executorResults(bindings);
    wrongExecutor[0].executor = "fixture-self-asserted-executor";
    expect(() =>
      buildEnvironmentOutputSweepObservations(
        bindings,
        wrongExecutor,
        executorIdentity,
      ),
    ).toThrow(/stale|executor/u);

    for (const mutate of [
      (decision) => {
        decision.decisionSet.operationId = decision.decisionSet.operationId.replace(
          ":0:",
          ":7:",
        );
        decision.evidence.operationId = decision.decisionSet.operationId;
      },
      (decision) => {
        const packagePrincipal = {
          kind: "package",
          name: "image-lib",
          integrity: `sha256-${"F".repeat(43)}`,
          locator: "image-lib@2.4.1",
        };
        decision.decisionSet.context.actor = structuredClone(packagePrincipal);
        decision.decisionSet.context.constrainedPrincipals = [
          structuredClone(packagePrincipal),
        ];
        decision.decisionSet.effects[0].effectOwner =
          structuredClone(packagePrincipal);
        decision.evidence.actor = structuredClone(packagePrincipal);
        decision.evidence.effectOwners = [structuredClone(packagePrincipal)];
        decision.evidence.constrainedPrincipals = [
          structuredClone(packagePrincipal),
        ];
        decision.evidence.evidence[0].principal =
          structuredClone(packagePrincipal);
      },
      (decision) => {
        decision.decisionSet.context.constrainedPrincipals.push({
          kind: "runtime",
          identity: "unexpected-runtime",
        });
        decision.evidence.constrainedPrincipals = structuredClone(
          decision.decisionSet.context.constrainedPrincipals,
        );
      },
      (decision) => {
        decision.evidence.generations.dynamic += 1;
      },
    ]) {
      const drifted = executorResults(bindings);
      mutate(drifted[0].phases[0].typedDecisions[0]);
      expect(() =>
        buildEnvironmentOutputSweepObservations(
          bindings,
          drifted,
          executorIdentity,
        ),
      ).toThrow(/root|route|state|binding|operation|principal|generation/u);
    }

    for (const mutateAll of [
      (decision) => {
        decision.decisionSet.context.actor.identity = "coordinated-other-root";
        decision.decisionSet.context.constrainedPrincipals[0].identity =
          "coordinated-other-root";
        decision.decisionSet.effects[0].effectOwner.identity =
          "coordinated-other-root";
        decision.evidence.actor.identity = "coordinated-other-root";
        decision.evidence.effectOwners[0].identity =
          "coordinated-other-root";
        decision.evidence.constrainedPrincipals[0].identity =
          "coordinated-other-root";
        decision.evidence.evidence[0].principal.identity =
          "coordinated-other-root";
      },
      (decision) => {
        decision.evidence.generations = {
          negative: 1,
          dynamic: 2,
          handle: 3,
        };
      },
    ]) {
      const drifted = executorResults(bindings);
      for (const phase of drifted[0].phases) {
        for (const typedDecision of phase.typedDecisions) {
          mutateAll(typedDecision);
        }
      }
      expect(() =>
        buildEnvironmentOutputSweepObservations(
          bindings,
          drifted,
          executorIdentity,
        ),
      ).toThrow(/fixture|generation|root/u);
    }

    for (const inject of [
      (results) => {
        results[0].phases[0].typedDecisions[0].evidence.rawEnvironmentValue =
          "DO_NOT_PUBLISH_SECRET";
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].decisionSet.effects[0].resource.rawEnvironmentValue =
          "DO_NOT_PUBLISH_SECRET";
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].evidence.identity.rawEnvironmentValue =
          "DO_NOT_PUBLISH_SECRET";
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].evidence.evidence[0].reason =
          "DO_NOT_PUBLISH_SECRET";
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].evidence.evidence[0].stratum =
          "DO_NOT_PUBLISH_SECRET";
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].evidence.evidence[0].sourceId =
          "DO_NOT_PUBLISH_SECRET";
      },
      (results) => {
        results[0].phases[0].typedDecisions[0].evidence.evidence[0].principal =
          null;
      },
      (results) => {
        const evidence =
          results[0].phases[0].typedDecisions[0].evidence.evidence;
        evidence.push(structuredClone(evidence[0]));
      },
    ]) {
      const secretBearing = executorResults(bindings);
      inject(secretBearing);
      expect(() =>
        buildEnvironmentOutputSweepObservations(
          bindings,
          secretBearing,
          executorIdentity,
        ),
      ).toThrow(/unexpected fields|static floor|source ID|principal|evidence/u);
    }
  });
});
