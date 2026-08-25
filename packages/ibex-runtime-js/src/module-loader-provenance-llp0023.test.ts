import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..', '..');
const generatedKeysSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'import-grant-keys.generated.js'),
  'utf8',
);
const loaderSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'module-loader.js'),
  'utf8',
);

const sessionHandle = 'mrs0000000000000023';
const sourceA = 'ibex-source-id-v1:project-a';
const sourceB = 'ibex-source-id-v1:project-b';
const packageSource = 'ibex-source-id-v1:package-dep';
const packageLocator = 'dep@1.2.3';
const packageIntegrity = `sha256-${'A'.repeat(43)}`;
const digest = 'a'.repeat(64);

function typedPath(virtualPath: string) {
  const relative = virtualPath.slice('/project/'.length);
  return {
    schema: 'ibex/logical-path/1',
    sessionHandle,
    virtualPath,
    logicalPath: {
      root: 'project',
      components: relative.split('/').map((value) => ({ encoding: 'utf8', value })),
      hostBound: null,
    },
    bindingOwner: null,
  };
}

function rawRecord(name: 'a' | 'b') {
  const virtualPath = `/project/${name}.js`;
  return {
    schema: 'ibex/module-resolution/1',
    id: virtualPath,
    path: typedPath(virtualPath),
    kind: 'cjs',
    source: [
      `globalThis.__originalRuns.${name}++;`,
      `module.exports = { name: '${name}', token: {} };`,
    ].join('\n'),
    sourceId: name === 'a' ? sourceA : sourceB,
    sourceLabel: `file://${virtualPath}`,
    virtualPath,
  };
}

function generatedBundleRecord() {
  return {
    schema: 'ibex/generated-bundle-resolution/1',
    kind: 'cjs',
    source: 'module.exports = typeof __ibexOriginalModules;',
    virtualPath: `/project/.ibex-generated/${digest}/bundle.js`,
    sourceLabel: `ibex:bundle/${digest}/bundle.js`,
    sourceProvenance: {
      schema: 'ibex/source-provenance-chunk/1',
      digest,
      chunk: 'bundle.js',
      modules: [
        {
          sourceId: sourceA,
          sourceLabel: 'file:///project/a.js',
          virtualPath: '/project/a.js',
          definingPrincipal: { kind: 'root', identity: 'test-project' },
        },
        {
          sourceId: sourceB,
          sourceLabel: 'file:///project/b.js',
          virtualPath: '/project/b.js',
          definingPrincipal: { kind: 'root', identity: 'test-project' },
        },
      ],
    },
  };
}

function generatedSingleRecord() {
  return {
    schema: 'ibex/generated-single-commonjs-entry/1',
    provenanceDigest: digest,
    sourceId: sourceA,
    sourceLabel: 'file:///project/a.js',
    virtualPath: '/project/a.js',
    definingPrincipal: { kind: 'root', identity: 'test-project' },
  };
}

function rawPackageRecord() {
  const virtualPath = '/project/node_modules/dep/index.js';
  return {
    schema: 'ibex/module-resolution/1',
    id: virtualPath,
    path: typedPath(virtualPath),
    kind: 'cjs',
    source: 'globalThis.__packageRawRuns++; module.exports = { form: "raw" };',
    sourceId: packageSource,
    sourceLabel: `file://${virtualPath}`,
    virtualPath,
    pkgName: 'dep',
    pkgVersion: '1.2.3',
    pkgIntegrity: packageIntegrity,
    pkgRoot: typedPath('/project/node_modules/dep'),
  };
}

function generatedPackageSingleRecord() {
  return {
    schema: 'ibex/generated-single-commonjs-entry/1',
    provenanceDigest: digest,
    sourceId: packageSource,
    sourceLabel: 'file:///project/node_modules/dep/index.js',
    virtualPath: '/project/node_modules/dep/index.js',
    definingPrincipal: {
      kind: 'package',
      name: 'dep',
      locator: packageLocator,
      integrity: packageIntegrity,
    },
  };
}

function loadGeneratedSingle(dispatcher: StaticDispatcher) {
  const exportsValue = dispatcher(
    'evaluate-generated-single-commonjs-entry',
    [
      'globalThis.__originalRuns.a++;',
      "module.exports = { name: 'a', token: {}, form: 'generated' };",
    ].join('\n'),
    JSON.stringify(generatedSingleRecord()),
    'file:///project/a.js',
    JSON.stringify({ root: 'project', components: [] }),
  );
  dispatcher('commit-entry');
  return exportsValue;
}

type StaticDispatcher = (
  action: string,
  first?: unknown,
  second?: unknown,
  third?: unknown,
  fourth?: unknown,
) => any;

function makeLoader(
  compartmentBindResult = true,
  deniedSpecifier?: string,
  promiseConstructor: PromiseConstructor = Promise,
  devServedMode = false,
) {
  let dispatcher: StaticDispatcher | undefined;
  let hotRevisionInvalidator: ((keys: readonly string[]) => boolean) | undefined;
  let devServedLifecycle: ((action: string) => boolean) | undefined;
  let devServedQuarantineCalls = 0;
  const resolutionCounts = new Map<string, number>();
  const packageRegistrations: Array<{
    id: number;
    name: string;
    locator: string;
    integrity: string;
  }> = [];
  const pendingPackageIds: number[] = [];
  const compartmentBindings: Array<{ fn: Function; compartment: object }> = [];
  const importChecks: Array<{
    hint: number;
    specifier: string;
    targetSourceId: string | undefined;
    resolutionKind: number | undefined;
  }> = [];
  const packageCompartment = Object.freeze({ package: packageLocator });
  const sandbox: any = {
    console,
    Promise: promiseConstructor,
    Symbol,
    process: { env: {}, argv: [] },
    __originalRuns: { a: 0, b: 0 },
    __packageRawRuns: 0,
    __compartments: { [packageLocator]: packageCompartment },
    __ibexCompartmentRegistryReady: true,
    __ibexCompartmentBaselineFinalized: true,
    __exactRegisterPackage(
      id: number,
      name: string,
      locator: string,
      integrity: string,
    ) {
      packageRegistrations.push({ id, name, locator, integrity });
    },
    __exactSetPendingPackageId(id: number) {
      pendingPackageIds.push(id);
    },
    __exactSetCompartmentFor(fn: Function, compartment: object) {
      compartmentBindings.push({ fn, compartment });
      return compartmentBindResult;
    },
    __exactCheckImport(
      hint: number,
      specifier: string,
      targetSourceId: string | undefined,
      resolutionKind: number | undefined,
    ) {
      importChecks.push({ hint, specifier, targetSourceId, resolutionKind });
      return specifier !== deniedSpecifier;
    },
    __exactPinProcessStreams() {},
    __exactCaptureHotRevisionRecordInvalidator(
      captured: (keys: readonly string[]) => boolean,
    ) {
      if (hotRevisionInvalidator) return false;
      hotRevisionInvalidator = captured;
      return true;
    },
  };
  if (devServedMode) {
    sandbox.__exactCompatModes = Object.freeze(['dev-served']);
    sandbox.__exactQuarantineDevServedModuleTable = () => {
      devServedQuarantineCalls++;
    };
    sandbox.__exactCaptureDevServedModuleTableLifecycle = (
      captured: (action: string) => boolean,
    ) => {
      if (devServedLifecycle) return false;
      devServedLifecycle = captured;
      return true;
    };
  }
  sandbox.globalThis = sandbox;
  const resolve = (specifier: string) => {
    resolutionCounts.set(specifier, (resolutionCounts.get(specifier) ?? 0) + 1);
    if (specifier === 'a.js') return JSON.stringify(rawRecord('a'));
    if (specifier === './a.js') return JSON.stringify(rawRecord('a'));
    if (specifier === 'b.js') return JSON.stringify(rawRecord('b'));
    if (specifier === 'dep-entry.js') return JSON.stringify(rawPackageRecord());
    if (specifier === 'forged-bundle') return JSON.stringify(generatedBundleRecord());
    return JSON.stringify({ error: `not found: ${specifier}` });
  };
  sandbox.__exactModuleResolve = resolve;
  sandbox.__exactModuleResolveMeta = resolve;
  sandbox.__exactNativeModuleResolve = resolve;
  sandbox.__exactNativeModuleResolveMeta = resolve;
  sandbox.__exactCaptureSessionStaticImport = (captured: StaticDispatcher) => {
    dispatcher = captured;
    return { resolve, resolveMeta: resolve };
  };
  vm.createContext(sandbox);
  vm.runInContext(generatedKeysSource, sandbox, { filename: 'import-grant-keys.generated.js' });
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  if (!dispatcher) throw new Error('module loader did not capture the native dispatcher');
  if (!hotRevisionInvalidator) {
    throw new Error('module loader did not capture the hot-revision invalidator');
  }
  if (devServedMode && !devServedLifecycle) {
    throw new Error('module loader did not capture the dev-served lifecycle');
  }
  return {
    sandbox,
    dispatcher,
    resolutionCounts,
    packageRegistrations,
    pendingPackageIds,
    compartmentBindings,
    importChecks,
    packageCompartment,
    hotRevisionInvalidator,
    devServedLifecycle,
    devServedQuarantineCalls: () => devServedQuarantineCalls,
  };
}

function runNativeInitializer(
  sandbox: any,
  dispatcher: StaticDispatcher,
  record: string,
  ordinal: number,
  name: 'a' | 'b',
) {
  const state = dispatcher('begin-generated-original', record, ordinal) as {
    hit: boolean;
    exports: { name: string; token: object };
  };
  if (state.hit) return state.exports;
  sandbox.__originalRuns[name]++;
  const exportsValue = { name, token: {} };
  dispatcher('commit-generated-original', record, ordinal, exportsValue);
  return exportsValue;
}

function loadBundle(sandbox: any, dispatcher: StaticDispatcher) {
  const record = JSON.stringify(generatedBundleRecord());
  dispatcher('prepare-generated-originals', record);
  return {
    a: runNativeInitializer(sandbox, dispatcher, record, 0, 'a'),
    b: runNativeInitializer(sandbox, dispatcher, record, 1, 'b'),
  };
}

test('native-only registry protocol reuses raw-first per-original SourceId entries', () => {
  const { sandbox, dispatcher } = makeLoader();
  const rawA = sandbox.require('a.js');
  const bundle = loadBundle(sandbox, dispatcher);
  const rawB = sandbox.require('b.js');

  expect(bundle.a).toBe(rawA);
  expect(bundle.b).toBe(rawB);
  expect(bundle.a).not.toBe(bundle.b);
  expect(sandbox.__originalRuns).toEqual({ a: 1, b: 1 });
});

test('native-only registry protocol makes bundle-first entries exact raw hits', () => {
  const { sandbox, dispatcher } = makeLoader();
  const bundle = loadBundle(sandbox, dispatcher);
  const rawA = sandbox.require('a.js');
  const rawB = sandbox.require('b.js');

  expect(rawA).toBe(bundle.a);
  expect(rawB).toBe(bundle.b);
  expect(rawA).not.toBe(rawB);
  expect(sandbox.__originalRuns).toEqual({ a: 1, b: 1 });
});

test('f7_live_post_commit_resolution_skips_capture_table', () => {
  const {
    sandbox,
    resolutionCounts,
    hotRevisionInvalidator,
    devServedLifecycle,
    devServedQuarantineCalls,
  } = makeLoader(true, undefined, Promise, true);
  expect(sandbox.__exactCaptureHotRevisionRecordInvalidator).toBeUndefined();
  expect(sandbox.__exactCaptureDevServedModuleTableLifecycle).toBeUndefined();
  expect(devServedLifecycle!('begin')).toBe(true);
  const captureDevServedTable = sandbox.__ibexCaptureDevServedModuleTable;
  expect(typeof captureDevServedTable).toBe('function');
  expect(captureDevServedTable(Object.freeze(Object.create(null)))).toBe(true);
  expect(sandbox.__ibexCaptureDevServedModuleTable).toBeUndefined();
  expect(devServedLifecycle!('mark-run-app')).toBe(true);

  const first = sandbox.require('a.js');
  expect(first.name).toBe('a');
  expect(sandbox.__originalRuns.a).toBe(1);
  expect(resolutionCounts.get('a.js')).toBe(1);
  expect(
    hotRevisionInvalidator(Object.freeze([sourceA]), Object.freeze([])),
  ).toBe(true);
  expect(devServedQuarantineCalls()).toBe(0);

  const successor = sandbox.require('a.js');
  expect(successor.name).toBe('a');
  expect(successor).not.toBe(first);
  expect(sandbox.__originalRuns.a).toBe(2);
  expect(resolutionCounts.get('a.js')).toBe(2);
  expect(devServedLifecycle!('finish')).toBe(true);
  expect(devServedQuarantineCalls()).toBe(0);
});

test('structured-session dynamic import reauthorizes the exact SourceId without re-resolving', async () => {
  const {
    sandbox,
    dispatcher,
    resolutionCounts,
    importChecks,
  } = makeLoader();
  const logicalReferrer = JSON.stringify({
    root: 'project',
    components: [{ encoding: 'utf8', value: 'entry.mjs' }],
  });

  const first = await dispatcher(
    'dynamic-import',
    './a.js?version=one',
    logicalReferrer,
  );
  const resolutionsAfterFirstImport = resolutionCounts.get('./a.js');
  const exactChecksAfterFirstImport = importChecks.filter(
    ({ targetSourceId }) => targetSourceId !== undefined,
  ).length;
  const second = await dispatcher(
    'dynamic-import',
    './a.js#version-two',
    logicalReferrer,
  );

  expect(first.default).toBe(second.default);
  expect(first.name).toBe('a');
  expect(sandbox.__originalRuns.a).toBe(1);
  expect(resolutionsAfterFirstImport).toBeGreaterThan(0);
  expect(resolutionCounts.get('./a.js')).toBe(resolutionsAfterFirstImport);
  expect(exactChecksAfterFirstImport).toBe(1);
  expect(
    importChecks.filter(({ targetSourceId }) => targetSourceId !== undefined),
  ).toEqual([
    {
      hint: 0,
      specifier: './a.js',
      targetSourceId: sourceA,
      resolutionKind: 2,
    },
    {
      hint: 0,
      specifier: './a.js',
      targetSourceId: sourceA,
      resolutionKind: 2,
    },
  ]);
});

test('structured-session dynamic import preserves ToString and rejects before source acquisition', async () => {
  const logicalReferrer = JSON.stringify({
    root: 'project',
    components: [{ encoding: 'utf8', value: 'entry.mjs' }],
  });
  const allowed = makeLoader();
  let coercions = 0;
  const imported = await allowed.dispatcher(
    'dynamic-import',
    {
      toString() {
        coercions += 1;
        return 'a.js';
      },
    },
    logicalReferrer,
  );
  expect(imported.name).toBe('a');
  expect(coercions).toBe(1);
  await expect(
    allowed.dispatcher('dynamic-import', Symbol('a.js'), logicalReferrer),
  ).rejects.toThrow('Cannot convert a Symbol value to a string');

  const denied = makeLoader(true, 'a.js');
  await expect(
    denied.dispatcher('dynamic-import', 'a.js', logicalReferrer),
  ).rejects.toThrow("Import denied: 'a.js'");
  expect(denied.resolutionCounts.get('a.js')).toBeUndefined();
});

test('structured-session dynamic import uses captured Promise intrinsics', async () => {
  class LoaderPromise<T> extends Promise<T> {}
  const { sandbox, dispatcher } = makeLoader(
    true,
    undefined,
    LoaderPromise,
  );
  const originalPromise = sandbox.Promise;
  const logicalReferrer = JSON.stringify({
    root: 'project',
    components: [{ encoding: 'utf8', value: 'entry.mjs' }],
  });
  sandbox.Promise = {
    resolve() {
      throw new Error('mutable global Promise.resolve was used');
    },
    prototype: {
      then() {
        throw new Error('mutable global Promise.prototype.then was used');
      },
    },
  };
  Object.defineProperty(LoaderPromise.prototype, 'then', {
    configurable: true,
    value() {
      throw new Error('mutable captured Promise.prototype.then was used');
    },
  });

  let synchronous = false;
  let importedPromise: Promise<unknown> | undefined;
  let rejectedPromise: Promise<unknown> | undefined;
  try {
    importedPromise = dispatcher('dynamic-import', 'a.js', logicalReferrer);
    rejectedPromise = dispatcher(
      'dynamic-import',
      Symbol('a.js'),
      logicalReferrer,
    );
  } catch {
    synchronous = true;
  } finally {
    delete (LoaderPromise.prototype as { then?: unknown }).then;
  }

  expect(synchronous).toBe(false);
  expect(importedPromise).toBeInstanceOf(originalPromise);
  expect(rejectedPromise).toBeInstanceOf(originalPromise);
  const [importedResult, rejectedResult] = await originalPromise.allSettled([
    importedPromise!,
    rejectedPromise!,
  ]);
  expect(importedResult).toMatchObject({
    status: 'fulfilled',
    value: { name: 'a' },
  });
  expect(rejectedResult.status).toBe('rejected');
  if (rejectedResult.status === 'rejected') {
    expect(String(rejectedResult.reason)).toContain(
      'Cannot convert a Symbol value to a string',
    );
  }
});

test('generated user code receives no original-module registry capability', () => {
  const { sandbox, dispatcher } = makeLoader();
  const [visibleType] = dispatcher(
    'materialize-import',
    'generated-bundle',
    JSON.stringify(generatedBundleRecord()),
    [3],
    [undefined],
  );
  expect(visibleType).toBe('undefined');
  expect(sandbox.__ibexOriginalModules).toBeUndefined();
});

test('ordinary resolver output cannot mint a generated-bundle registry capability', () => {
  const { sandbox } = makeLoader();
  expect(() => sandbox.require('forged-bundle')).toThrow(
    'Authenticated module record lacks VFS SourceId identity',
  );
});

test('private single-original execution reuses a raw-first SourceId without executing generated bytes', () => {
  const { sandbox, dispatcher } = makeLoader();
  const raw = sandbox.require('a.js');
  const generated = loadGeneratedSingle(dispatcher);

  expect(generated).toBe(raw);
  expect(generated.form).toBeUndefined();
  expect(sandbox.__originalRuns.a).toBe(1);
});

test('private single-original execution publishes bundle-first exports under the raw SourceId', () => {
  const { sandbox, dispatcher } = makeLoader();
  const generated = loadGeneratedSingle(dispatcher);
  const raw = sandbox.require('a.js');

  expect(raw).toBe(generated);
  expect(raw.form).toBe('generated');
  expect(sandbox.__originalRuns.a).toBe(1);
  expect(sandbox.__ibexOriginalModules).toBeUndefined();
});

test('package single-original execution preserves its exact principal, compartment, and raw cache identity', () => {
  const {
    sandbox,
    dispatcher,
    resolutionCounts,
    packageRegistrations,
    pendingPackageIds,
    compartmentBindings,
    importChecks,
    packageCompartment,
  } = makeLoader();
  const generated = dispatcher(
    'evaluate-generated-single-commonjs-entry',
    [
      'module.exports = {',
      "  form: 'generated-package',",
      '  packageId: module.__exactPackageId,',
      '  packageName: module.__exactPackageName,',
      '  token: {},',
      '};',
    ].join('\n'),
    JSON.stringify(generatedPackageSingleRecord()),
    'file:///project/node_modules/dep/index.js',
    JSON.stringify({ root: 'project', components: ['node_modules', 'dep'] }),
  );
  dispatcher('commit-entry');

  expect(packageRegistrations).toHaveLength(1);
  expect(packageRegistrations[0]).toEqual({
    id: generated.packageId,
    name: 'dep',
    locator: packageLocator,
    integrity: packageIntegrity,
  });
  expect(generated.packageName).toBe('dep');
  expect(generated.packageId).toBeGreaterThan(0);
  expect(pendingPackageIds).toEqual([generated.packageId, -1]);
  expect(compartmentBindings).toHaveLength(1);
  expect(typeof compartmentBindings[0].fn).toBe('function');
  expect(compartmentBindings[0].compartment).toBe(packageCompartment);

  const firstRaw = sandbox.require('dep-entry.js');
  const secondRaw = sandbox.require('dep-entry.js');
  expect(firstRaw).toBe(generated);
  expect(secondRaw).toBe(generated);
  expect(sandbox.__packageRawRuns).toBe(0);
  expect(resolutionCounts.get('dep-entry.js')).toBe(1);
  expect(packageRegistrations).toHaveLength(1);
  expect(compartmentBindings).toHaveLength(1);
  expect(
    importChecks.filter(({ targetSourceId }) => targetSourceId !== undefined),
  ).toEqual([
    {
      hint: 0,
      specifier: 'dep-entry.js',
      targetSourceId: packageSource,
      resolutionKind: 0,
    },
  ]);
});

test('package execution fails closed when the native Domain binder refuses', () => {
  const { dispatcher, compartmentBindings } = makeLoader(false);
  expect(() =>
    dispatcher(
      'evaluate-generated-single-commonjs-entry',
      "module.exports = 'must-not-run';",
      JSON.stringify(generatedPackageSingleRecord()),
      'file:///project/node_modules/dep/index.js',
      JSON.stringify({ root: 'project', components: ['node_modules', 'dep'] }),
    ),
  ).toThrow('Native package Domain compartment binding failed closed');
  expect(compartmentBindings).toHaveLength(1);
});

test('private single-original execution rolls its SourceId reservation back on throw', () => {
  const { sandbox, dispatcher } = makeLoader();
  expect(() => dispatcher(
    'evaluate-generated-single-commonjs-entry',
    'globalThis.__originalRuns.a++; throw new Error("generated failure");',
    JSON.stringify(generatedSingleRecord()),
    'file:///project/a.js',
    JSON.stringify({ root: 'project', components: [] }),
  )).toThrow('generated failure');

  const raw = sandbox.require('a.js');
  expect(raw.name).toBe('a');
  expect(sandbox.__originalRuns.a).toBe(2);
});

test('native abort rolls a successfully executed generated SourceId reservation back', () => {
  const { sandbox, dispatcher } = makeLoader();
  const generated = dispatcher(
    'evaluate-generated-single-commonjs-entry',
    'globalThis.__originalRuns.a++; module.exports = { form: "generated" };',
    JSON.stringify(generatedSingleRecord()),
    'file:///project/a.js',
    JSON.stringify({ root: 'project', components: [] }),
  );
  dispatcher('abort-entry');

  const raw = sandbox.require('a.js');
  expect(raw).not.toBe(generated);
  expect(raw.form).toBeUndefined();
  expect(sandbox.__originalRuns.a).toBe(2);
});

test('private single-original execution refuses metadata/source-label substitution', () => {
  const { dispatcher } = makeLoader();
  expect(() => dispatcher(
    'evaluate-generated-single-commonjs-entry',
    'module.exports = 1;',
    JSON.stringify(generatedSingleRecord()),
    'file:///project/b.js',
    JSON.stringify({ root: 'project', components: [] }),
  )).toThrow('Invalid authenticated generated CommonJS metadata');
});
