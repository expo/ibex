// Closed source-to-executor routing for promotion-facing public fixtures.
// The rich recipe owns the exact command. This table independently names the
// harness that command is permitted to claim, so executed evidence cannot
// choose or relabel its own executor.
//
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — each
// fixture must execute its authored public route rather than borrow a generic
// adapter or another batch's result.

const FEATURES = "capsec-conformance-observer,openssl-crypto";
const command = (testName, nocapture = false) => [
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  FEATURES,
  testName,
  "--",
  "--test-threads=1",
  ...(nocapture ? ["--nocapture"] : []),
];

export const PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS = Object.freeze(
  [
    [
      "capsec_public_builtin_recipe_batch",
      "ibex-builtin-public-surface-harness",
      true,
    ],
    [
      "capsec_public_callback_invariant_batch",
      "ibex-callback-invariant-public-harness",
      false,
    ],
    [
      "capsec_public_closed_recipe_batch",
      "ibex-closed-public-surface-harness",
      false,
    ],
    [
      "capsec_public_native_recipe_batch",
      "ibex-native-public-surface-harness",
      false,
    ],
    [
      "capsec_public_noncap_builtin_recipe_batch",
      "ibex-noncap-builtin-public-surface-harness",
      true,
    ],
    [
      "capsec_public_startup_batch",
      "ibex-startup-public-surface-harness",
      false,
    ],
    [
      "capsec_public_startup_environment_batch",
      "ibex-startup-environment-public-source-harness",
      false,
    ],
    [
      "capsec_public_target_absence_batch",
      "ibex-target-absence-public-surface-harness",
      false,
    ],
  ].map(([testName, executor, nocapture]) =>
    Object.freeze({
      testName,
      executor,
      command: Object.freeze(command(testName, nocapture)),
    }),
  ),
);

const descriptorByExactCommand = new Map(
  PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS.map((descriptor) => [
    JSON.stringify(descriptor.command),
    descriptor,
  ]),
);

export function publicSurfaceExecutorDescriptor(publicCommand) {
  if (
    !Array.isArray(publicCommand) ||
    publicCommand.length === 0 ||
    !publicCommand.every(
      (part) => typeof part === "string" && part.length > 0,
    )
  ) {
    throw new Error("public fixture command is malformed");
  }
  const descriptor = descriptorByExactCommand.get(JSON.stringify(publicCommand));
  if (!descriptor) {
    throw new Error(
      `public fixture command has no reviewed executor: ${JSON.stringify(publicCommand)}`,
    );
  }
  return descriptor;
}

export function reviewedPublicSurfaceExecutorDescriptor(publicCommand) {
  if (!Array.isArray(publicCommand)) return null;
  return descriptorByExactCommand.get(JSON.stringify(publicCommand)) ?? null;
}

export function publicSurfaceExecutorForRecipe(recipe) {
  if (
    recipe?.status !== "fully-executable" ||
    recipe.publicSurfaceProbe?.kind === undefined
  ) {
    throw new Error(
      `${recipe?.fixtureId ?? "unknown fixture"}: executor requires one complete public recipe`,
    );
  }
  return publicSurfaceExecutorDescriptor(recipe.publicSurfaceProbe.command)
    .executor;
}
