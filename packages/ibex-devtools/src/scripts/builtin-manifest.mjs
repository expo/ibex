import runtimeModuleManifest from '../../../../src/builtins/helpers/runtime-module-manifest.cjs';

export default runtimeModuleManifest;

export const {
  bundlerExternalModules,
  moduleBuiltinList,
  moduleBuiltinRuntimeSpecifiers,
  nodeBuiltins,
  nodeOnlyBuiltinModules,
  publicBuiltins,
  registryEntries,
  reservedNodeOnlyBuiltins,
  staticBootstrapInternalModules,
} = runtimeModuleManifest;
