// TEST ONLY. This injectable harness is permanently bound to distinct
// test-only store roots and local record schemas inside the core. It cannot
// materialize a production `target/hermes-artifacts` store.

export {
  buildFixedVerifierExpectationsTestOnly as buildFixedVerifierExpectations,
  detectMacOsExtendedAclTestOnly as detectMacOsExtendedAcl,
  installPortableEngineTestOnly as installPortableEngine,
  installPortableEngineWithPromotionLineageTestOnly as installPortableEngineWithPromotionLineage,
  listCheckedRevisionFilesTestOnly as listCheckedRevisionFiles,
  readCheckedRevisionFileTestOnly as readCheckedRevisionFile,
  resolveGitControlPathsTestOnly as resolveGitControlPaths,
  validateGitControlPlaneTestOnly as validateGitControlPlane,
  verifyPortableEngineStoreTestOnly as verifyPortableEngineStore,
} from "./portable-engine-installer-core.mjs";
