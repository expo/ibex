// Loader-boundary regression coverage for LLP 0022 runtime grant refusal.
// The check is argument-count-only: it must not touch a getter/Proxy and must
// run before resolution even when the loader function has been aliased.

import { expect, test } from 'bun:test';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const generatedKeysSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'import-grant-keys.generated.js'),
  'utf8',
);
const loaderSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'module-loader.js'),
  'utf8',
);
const streamEnhanceSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'stream-enhance.js'),
  'utf8',
);

const packageOwner = {
  kind: 'package',
  name: 'image-lib',
  integrity: 'sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA',
  locator: 'image-lib@2.4.1',
};
const resolverSessionHandle = 'mrs0000000000000001';

type CapturedStaticImport = {
  (
    action: 'materialize-import',
    specifier: string,
    record: string,
    kinds: number[],
    importedNames: Array<string | undefined>,
  ): unknown[];
  (
    action: string,
    first?: unknown,
    second?: unknown,
    third?: unknown,
    fourth?: unknown,
  ): unknown;
};

function typedPath(virtualPath: string, packageRoot?: string) {
  const relative = packageRoot
    ? virtualPath.slice(packageRoot.length).replace(/^\//, '')
    : virtualPath.slice('/project'.length).replace(/^\//, '');
  return {
    schema: 'ibex/logical-path/1',
    sessionHandle: resolverSessionHandle,
    virtualPath,
    logicalPath: {
      root: packageRoot ? 'package' : 'project',
      components: relative
        ? relative.split('/').map((value) => ({ encoding: 'utf8', value }))
        : [],
      hostBound: null,
    },
    bindingOwner: packageRoot ? packageOwner : null,
  };
}

function authenticatedRecord(
  virtualPath: string,
  source: string,
  packageRoot?: string,
) {
  return {
    schema: 'ibex/module-resolution/1',
    id: virtualPath,
    path: typedPath(virtualPath, packageRoot),
    kind: 'cjs',
    source,
    sourceId: `ibex-source-id-v1:${virtualPath}`,
    sourceLabel: `file://${virtualPath}`,
    virtualPath,
    ...(packageRoot ? {
      pkgName: 'image-lib',
      pkgRoot: typedPath(packageRoot, packageRoot),
      pkgVersion: '2.4.1',
      pkgIntegrity: 'sha256-authenticated',
    } : {}),
  };
}

function privateResolverPath(handle: string) {
  return {
    schema: 'ibex/private-resolver-ref/1',
    sessionHandle: resolverSessionHandle,
    handle,
    virtualPath: `/project/.ibex-resolver/${handle}`,
  };
}

function makeLoader(options: { deniedSpecifier?: string } = {}) {
  const resolutions: string[] = [];
  const resolverReferrers: Array<{ specifier: string; referrer: string }> = [];
  const metadataResolverCalls: Array<{ specifier: string; referrer: string }> = [];
  const importGateCalls: Array<{ hint: number; specifier: string }> = [];
  const packageRegistrations: Array<{
    id: number;
    selector: string;
    identity: string;
    integrity: string | undefined;
  }> = [];
  let capturedStaticImport: undefined | CapturedStaticImport;
  const sandbox: any = {
    console,
    Promise,
    Symbol,
    __exactPinProcessStreams() {},
    process: { env: {}, argv: [], mainModule: { secret: true } },
    setTimeout,
    clearTimeout,
  };
  sandbox.globalThis = sandbox;
  const resolveRecord = (specifier: string, referrer = '') => {
    resolutions.push(specifier);
    resolverReferrers.push({ specifier, referrer });
    if (specifier === 'static-dep.js') {
      return JSON.stringify(authenticatedRecord(
        '/project/static-dep.js',
        'module.exports = { identity: {} };',
      ));
    }
    if (specifier === './package-child.js') {
      return JSON.stringify(authenticatedRecord(
        '/project/node_modules/image-lib/package-child.js',
        'module.exports = { id: module.__exactPackageId, root: module.__exactPackageRoot };',
        '/project/node_modules/image-lib',
      ));
    }
    if (specifier === 'data.json') {
      return JSON.stringify({
        ...authenticatedRecord('/project/data.json', '{"loaded":true}'),
        kind: 'json',
      });
    }
    if (specifier === 'probe.js') {
      return JSON.stringify(authenticatedRecord(
        '/project/probe.js',
        [
          "var resolveAlias = require.resolve;",
          "var resolveRefused = false;",
          "try { resolveAlias('data.json', {}); } catch (_) { resolveRefused = true; }",
          "module.exports = {",
          "  mainDescriptor: Object.getOwnPropertyDescriptor(require, 'main'),",
          "  cacheDescriptor: Object.getOwnPropertyDescriptor(require, 'cache'),",
          "  packageRootDescriptor: Object.getOwnPropertyDescriptor(module, '__exactPackageRoot'),",
          "  resolveRefused: resolveRefused",
          "};",
        ].join('\n'),
      ));
    }
    if (specifier === 'resolve-denied-probe.js') {
      return JSON.stringify(authenticatedRecord(
        '/project/resolve-denied-probe.js',
        [
          "try { require.resolve('blocked-pkg'); }",
          "catch (error) { module.exports = { code: error.code, message: error.message }; }",
        ].join('\n'),
      ));
    }
    if (specifier === 'private-package.js') {
      return JSON.stringify({
        schema: 'ibex/module-resolution/1',
        id: '/project/.ibex-resolver/r0000000000000010',
        path: privateResolverPath('r0000000000000010'),
        pkgName: 'private-package',
        pkgRoot: privateResolverPath('r0000000000000011'),
        kind: 'cjs',
        source: "module.exports = Object.getOwnPropertyDescriptor(module, '__exactPackageRoot');",
      });
    }
    if (specifier === 'module' || specifier === 'node:module') {
      return JSON.stringify({
        id: 'module',
        kind: 'builtin',
        source: 'module.exports = { createRequire: module.__exactCreateRequire };',
      });
    }
    return JSON.stringify({ error: `not found: ${specifier}` });
  };
  const exactResolve = (specifier: string, referrer = '') =>
    resolveRecord(specifier, referrer);
  const exactResolveMeta = (specifier: string, referrer = '') => {
    metadataResolverCalls.push({ specifier, referrer });
    const record = JSON.parse(resolveRecord(specifier, referrer));
    delete record.source;
    return JSON.stringify(record);
  };
  sandbox.__exactModuleResolve = exactResolve;
  sandbox.__exactNativeModuleResolve = exactResolve;
  sandbox.__exactModuleResolveMeta = exactResolveMeta;
  sandbox.__exactNativeModuleResolveMeta = exactResolveMeta;
  sandbox.__exactCheckImport = (hint: number, specifier: string) => {
    importGateCalls.push({ hint, specifier });
    return specifier !== options.deniedSpecifier;
  };
  sandbox.__ibexBarePackageName = (identity: string) => identity.split('@')[0];
  sandbox.__exactRegisterPackage = (
    id: number,
    selector: string,
    identity: string,
    integrity: string | undefined,
  ) => {
    packageRegistrations.push({ id, selector, identity, integrity });
  };
  sandbox.__exactCaptureSessionStaticImport = (loader: typeof capturedStaticImport) => {
    capturedStaticImport = loader;
    return { resolve: exactResolve, resolveMeta: exactResolveMeta };
  };
  vm.createContext(sandbox);
  vm.runInContext(generatedKeysSource, sandbox, { filename: 'import-grant-keys.generated.js' });
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  vm.runInContext(streamEnhanceSource, sandbox, { filename: 'stream-enhance.js' });
  if (!capturedStaticImport) throw new Error('module loader did not register static imports');
  return {
    sandbox,
    resolutions,
    resolverReferrers,
    metadataResolverCalls,
    importGateCalls,
    packageRegistrations,
    capturedStaticImport,
  };
}

test('every require.resolve alias denies before metadata resolution', () => {
  const { sandbox, metadataResolverCalls, importGateCalls } = makeLoader({
    deniedSpecifier: 'blocked-pkg',
  });
  const assertDenied = (resolve: (specifier: string) => unknown) => {
    try {
      resolve('blocked-pkg');
      throw new Error('expected import denial');
    } catch (error: any) {
      expect(error.code).toBe('ERR_IBEX_IMPORT_DENIED');
    }
  };

  assertDenied(sandbox.require.resolve);
  assertDenied(sandbox.__exactRequire.resolve);
  const createRequire = sandbox.require('node:module').createRequire;
  assertDenied(createRequire('/project/tools/config.js').resolve);

  const local = sandbox.require('resolve-denied-probe.js');
  expect(local.code).toBe('ERR_IBEX_IMPORT_DENIED');
  expect(local.message).toContain("Import denied: 'blocked-pkg'");
  expect(
    metadataResolverCalls.some(({ specifier }) => specifier === 'blocked-pkg'),
  ).toBe(false);
  expect(
    importGateCalls.filter(({ specifier }) => specifier === 'blocked-pkg'),
  ).toHaveLength(4);
});

test('aliased require and require.resolve reject a second argument without reading it or resolving', () => {
  const { sandbox, resolutions } = makeLoader();
  let reads = 0;
  const options = Object.create(null);
  Object.defineProperty(options, 'needs', {
    get() {
      reads++;
      throw new Error('must not run');
    },
  });

  const requireAlias = sandbox.require;
  const beforeRequire = resolutions.length;
  expect(() => requireAlias('never-resolve', options)).toThrow('authorities');
  expect(resolutions.length).toBe(beforeRequire);
  expect(reads).toBe(0);

  const resolveAlias = sandbox.require.resolve;
  const beforeResolve = resolutions.length;
  expect(() => resolveAlias('never-resolve', options)).toThrow('needs');
  expect(resolutions.length).toBe(beforeResolve);
  expect(reads).toBe(0);
});

test('public dynamic-import aliases close second arguments before resolution', () => {
  const { sandbox, resolutions } = makeLoader();
  const before = resolutions.length;
  const dynamicAlias = sandbox.importModule;
  expect(() => dynamicAlias('never-resolve', new Proxy({}, {
    get() {
      throw new Error('must not run');
    },
  }))).toThrow('Runtime require options are not accepted');
  expect(resolutions.length).toBe(before);
});

test('live main/cache state is descriptor-absent on every retained loader facade', () => {
  const { sandbox } = makeLoader();
  expect(Object.getOwnPropertyDescriptor(sandbox.require, 'main')).toBeUndefined();
  expect(Object.getOwnPropertyDescriptor(sandbox.require, 'cache')).toBeUndefined();
  expect(Object.getOwnPropertyDescriptor(sandbox.__exactRequire, 'main')).toBeUndefined();
  expect(Object.getOwnPropertyDescriptor(sandbox.__exactRequire, 'cache')).toBeUndefined();
  const probe = sandbox.require('probe.js');
  expect(probe.mainDescriptor).toBeUndefined();
  expect(probe.cacheDescriptor).toBeUndefined();
  expect(probe.packageRootDescriptor).toBeUndefined();
  expect(() => sandbox.require('private-package.js')).toThrow(
    'Authenticated module record lacks VFS SourceId identity',
  );
  expect(probe.resolveRefused).toBe(true);
  expect(Object.getOwnPropertyDescriptor(sandbox.process, 'mainModule')).toBeUndefined();
});

test('armed bootstrap seals every raw native resolver alias after private capture', () => {
  const { sandbox, resolverReferrers } = makeLoader();
  for (const name of [
    '__exactModuleResolve',
    '__exactModuleResolveMeta',
    '__exactNativeModuleResolve',
    '__exactNativeModuleResolveMeta',
  ]) {
    expect(Object.getOwnPropertyDescriptor(sandbox, name)).toBeUndefined();
  }
  expect(sandbox.require.resolve('data.json')).toBe('/project/data.json');
  const createRequire = sandbox.require('node:module').createRequire;
  const scoped = createRequire('/project/tools/config.js');
  expect(scoped.resolve('data.json')).toBe('/project/data.json');
  const scopedCall = resolverReferrers
    .filter((call) => call.specifier === 'data.json')
    .at(-1);
  expect(JSON.parse(scopedCall!.referrer)).toEqual({
    schema: 'ibex/virtual-referrer/1',
    virtualPath: '/project/tools/config.js',
  });
});

test('JSON remains loadable by extension after inert type attributes are stripped upstream', () => {
  const { sandbox } = makeLoader();
  expect(sandbox.require('data.json')).toEqual({ loaded: true });
});

test('captured static loader ignores raw-loader tampering and shares cache identity', () => {
  const { sandbox, capturedStaticImport, resolverReferrers } = makeLoader();
  expect(Object.getOwnPropertyDescriptor(
    sandbox,
    '__exactCaptureSessionStaticImport',
  )).toBeUndefined();

  const rootRecord = JSON.stringify(authenticatedRecord(
    '/project/static-root.js',
    "module.exports = require('static-dep.js');",
  ));
  sandbox.require = () => { throw new Error('tampered raw require'); };
  sandbox.__exactModuleResolve = () => { throw new Error('tampered public resolver'); };
  sandbox.__exactNativeModuleResolve = sandbox.__exactModuleResolve;

  const first = capturedStaticImport(
    'materialize-import',
    'static-root.js',
    rootRecord,
    [3],
    [undefined],
  );
  const second = capturedStaticImport(
    'materialize-import',
    'static-root.js',
    rootRecord,
    [3],
    [undefined],
  );
  expect(first).toHaveLength(1);
  expect(second).toHaveLength(1);
  expect(first[0]).toBe(second[0]);
  expect((first[0] as { identity: object }).identity).toBe(
    (second[0] as { identity: object }).identity,
  );
  const staticReferrer = resolverReferrers.find((call) => call.specifier === 'static-dep.js');
  expect(staticReferrer).toBeDefined();
  expect(JSON.parse(staticReferrer!.referrer)).toEqual(
    expect.objectContaining({
      schema: 'ibex/logical-path/1',
      sessionHandle: resolverSessionHandle,
      virtualPath: '/project/static-root.js',
    }),
  );
});

test('captured static loader keeps authenticated package attribution across transitive edges', () => {
  const { capturedStaticImport, packageRegistrations } = makeLoader();
  const rootRecord = JSON.stringify(authenticatedRecord(
    '/project/node_modules/image-lib/index.js',
    [
      "var child = require('./package-child.js');",
      'module.exports = { root: module.__exactPackageId, child: child, packageRoot: module.__exactPackageRoot };',
    ].join('\n'),
    '/project/node_modules/image-lib',
  ));

  const [namespace] = capturedStaticImport(
    'materialize-import',
    'image-lib',
    rootRecord,
    [3],
    [undefined],
  ) as [{
    root: number;
    child: { id: number; root: any };
    packageRoot: any;
  }];
  expect(namespace.root).toBeGreaterThan(0);
  expect(namespace.child.id).toBe(namespace.root);
  expect(namespace.packageRoot.schema).toBe('ibex/logical-path/1');
  expect(namespace.packageRoot.sessionHandle).toBe(resolverSessionHandle);
  expect(namespace.packageRoot.virtualPath).toBe('/project/node_modules/image-lib');
  expect(namespace.child.root.virtualPath).toBe(namespace.packageRoot.virtualPath);
  expect(Object.isFrozen(namespace.packageRoot)).toBe(true);
  expect(packageRegistrations).toEqual([{
    id: namespace.root,
    selector: 'image-lib',
    identity: 'image-lib@2.4.1',
    integrity: 'sha256-authenticated',
  }]);
});

test('captured static loader performs named export Gets before returning to native', () => {
  const { capturedStaticImport } = makeLoader();
  const record = JSON.stringify(authenticatedRecord(
    '/project/throwing-export.js',
    [
      "Object.defineProperty(module.exports, 'boom', {",
      "  get: function () { throw new Error('binding get exploded'); }",
      '});',
    ].join('\n'),
  ));
  expect(() => capturedStaticImport(
    'materialize-import',
    'throwing-export.js',
    record,
    [2],
    ['boom'],
  ))
    .toThrow('binding get exploded');
});

test('captured direct CommonJS entry uses the wrapper, virtual referrer, and reserved cache', () => {
  const { capturedStaticImport, resolverReferrers, metadataResolverCalls } = makeLoader();
  const sourceId = 'ibex-source-id-v1:authenticated-direct-entry';
  const sourceLabel = 'file:///project/entry.cjs';
  const virtualPath = '/project/entry.cjs';
  const logicalReferrer = JSON.stringify({
    root: 'project',
    components: [],
    hostBound: null,
  });

  expect(capturedStaticImport(
    'reserve-entry',
    sourceId,
    sourceLabel,
    virtualPath,
  )).toBe(true);
  const result = capturedStaticImport(
    'evaluate-commonjs-entry',
    [
      'const await = 7;',
      'const initialExports = module.exports;',
      "const dependency = require('static-dep.js');",
      'module.exports = {',
      '  sloppyThis: this === initialExports,',
      '  exportsAlias: exports === initialExports,',
      '  awaitIdentifier: await,',
      '  filename: __filename,',
      '  dirname: __dirname,',
      '  moduleId: module.id,',
      '  moduleLoadedDuringBody: module.loaded,',
      "  stackLabel: new Error('entry stack').stack,",
      "  resolved: require.resolve('data.json'),",
      '  dependency: dependency,',
      '  requireMainType: typeof require.main,',
      '  processMainModuleType: typeof process.mainModule',
      '};',
    ].join('\n'),
    sourceLabel,
    virtualPath,
    logicalReferrer,
  ) as Record<string, any>;

  expect(result.sloppyThis).toBe(true);
  expect(result.exportsAlias).toBe(true);
  expect(result.awaitIdentifier).toBe(7);
  expect(result.filename).toBe('/project/entry.cjs');
  expect(result.dirname).toBe('/project');
  expect(result.moduleId).toBe('/project/entry.cjs');
  expect(result.moduleLoadedDuringBody).toBe(false);
  expect(result.stackLabel).toContain(sourceLabel);
  expect(result.resolved).toBe('/project/data.json');
  expect(result.dependency.identity).toBeDefined();
  expect(result.requireMainType).toBe('undefined');
  expect(result.processMainModuleType).toBe('undefined');
  expect(JSON.parse(
    resolverReferrers.find((call) => call.specifier === 'static-dep.js')!.referrer,
  )).toEqual(JSON.parse(logicalReferrer));
  expect(metadataResolverCalls).toEqual([
    { specifier: 'data.json', referrer: logicalReferrer },
  ]);
  expect(capturedStaticImport('commit-entry')).toBe(true);
});

test('captured direct CommonJS entry refuses top-level-await fallback and aborts cleanly', () => {
  const { capturedStaticImport } = makeLoader();
  const sourceId = 'ibex-source-id-v1:authenticated-direct-await';
  const sourceLabel = 'file:///project/await.cjs';
  const virtualPath = '/project/await.cjs';
  expect(capturedStaticImport(
    'reserve-entry',
    sourceId,
    sourceLabel,
    virtualPath,
  )).toBe(true);
  expect(() => capturedStaticImport(
    'evaluate-commonjs-entry',
    'await Promise.resolve(1);',
    sourceLabel,
    virtualPath,
    JSON.stringify({ root: 'project', components: [], hostBound: null }),
  )).toThrow();
  expect(capturedStaticImport('abort-entry')).toBe(true);
});
