// Test-only injectable boundary. It verifies only the differently named
// installer test store and cannot mint authority from a production store.

import { verifyPortableEngineStore } from "./portable-engine-installer-test-harness.mjs";
import { runPortableHermesCargoCore } from "./portable-engine-build-preflight-core.mjs";

export async function runPortableHermesCargoTestOnly(options, dependencies = {}) {
  return await runPortableHermesCargoCore(options, {
    verifyStore: (selection) => verifyPortableEngineStore(selection, dependencies.verifyDependencies ?? {}),
    spawnCargo: dependencies.spawnCargo,
    loadCargoTargetMap: dependencies.loadCargoTargetMap,
    requireCleanCheckout: dependencies.requireCleanCheckout,
  });
}
