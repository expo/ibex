import { afterEach, describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import vm from 'node:vm';
import { Request } from './fetch/Request';
import {
  Performance,
  PerformanceEntry,
  PerformanceMark,
  PerformanceMeasure,
  PerformanceObserver,
  performance as runtimePerformance,
} from './performance';
import { URL as RuntimeURL, URLSearchParams as RuntimeURLSearchParams } from './url';

const repoRoot = path.resolve(import.meta.dir, '../../..');
const loaderSource = readFileSync(
  path.join(repoRoot, 'src/engine/bootstrap/module-loader.js'),
  'utf8',
);
const urlBuiltinSource = readFileSync(
  path.join(repoRoot, 'src/builtins/url.js'),
  'utf8',
);
const perfHooksBuiltinSource = readFileSync(
  path.join(repoRoot, 'src/builtins/perf-hooks.js'),
  'utf8',
);
const nodeRequire = createRequire(import.meta.url);

const mutatedGlobalDescriptors = new Map<string, PropertyDescriptor | undefined>();

function replaceGlobal(name: string, value: unknown): void {
  if (!mutatedGlobalDescriptors.has(name)) {
    mutatedGlobalDescriptors.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  }
  Object.defineProperty(globalThis, name, {
    value,
    writable: true,
    configurable: true,
    enumerable: true,
  });
}

afterEach(() => {
  for (const [name, descriptor] of mutatedGlobalDescriptors) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete (globalThis as Record<string, unknown>)[name];
  }
  mutatedGlobalDescriptors.clear();
});

function evaluateBuiltin(source: string, sharedRuntimeBundle: boolean): unknown {
  const module = { exports: {} as unknown };
  const body = new Function(
    'require',
    'module',
    'exports',
    '__filename',
    '__dirname',
    '__exactDynamicImport',
    '__exactPrivateBuiltinBridges',
    source,
  );
  body(
    nodeRequire,
    module,
    module.exports,
    '/project/builtin.js',
    '/project',
    undefined,
    Object.freeze({ sharedRuntimeBundle }),
  );
  return module.exports;
}

describe('runtime-owned globals across late builtin imports', () => {
  test('loader captures the native shared-runtime phase before root-global rewrites', () => {
    const privateBridgeSource = `
      module.exports = {
        sharedRuntimeBundle: __exactPrivateBuiltinBridges.sharedRuntimeBundle,
        frozen: Object.isFrozen(__exactPrivateBuiltinBridges),
      };
    `;
    const sandbox: Record<string, any> = {
      console,
      Promise,
      Symbol,
      __exactHasSharedRuntimeBundle: true,
      __exactPinProcessStreams() {},
      __exactModuleResolve(specifier: string) {
        return JSON.stringify({ id: specifier, kind: 'builtin', source: privateBridgeSource });
      },
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });

    sandbox.__exactHasSharedRuntimeBundle = false;
    expect(sandbox.require('node:url')).toEqual({
      sharedRuntimeBundle: true,
      frozen: true,
    });
    expect(sandbox.require('node:perf_hooks')).toEqual({
      sharedRuntimeBundle: true,
      frozen: true,
    });
  });

  test('node:url and node:perf_hooks preserve canonical runtime globals and their consumers', () => {
    class RuntimePerformanceResourceTiming {}
    const canonicalGlobals: Record<string, unknown> = {
      URL: RuntimeURL,
      URLSearchParams: RuntimeURLSearchParams,
      performance: runtimePerformance,
      Performance,
      PerformanceEntry,
      PerformanceMark,
      PerformanceMeasure,
      PerformanceObserver,
      PerformanceResourceTiming: RuntimePerformanceResourceTiming,
    };
    for (const [name, value] of Object.entries(canonicalGlobals)) {
      replaceGlobal(name, value);
    }

    evaluateBuiltin(urlBuiltinSource, true);
    evaluateBuiltin(perfHooksBuiltinSource, true);

    for (const [name, value] of Object.entries(canonicalGlobals)) {
      expect((globalThis as Record<string, unknown>)[name]).toBe(value);
    }
    const request = new Request('https://example.com/ibex', {
      method: 'POST',
      body: 'ibex',
      headers: { 'content-type': 'text/plain' },
    });
    expect(request.url).toBe('https://example.com/ibex');
    expect(request.method).toBe('POST');
    expect(typeof globalThis.performance.setResourceTimingBufferSize).toBe('function');
  });

  test('legacy bootstrap without a shared runtime retains builtin global installation', () => {
    class BootstrapURL {}
    class BootstrapURLSearchParams {}
    const bootstrapPerformance = {};
    replaceGlobal('URL', BootstrapURL);
    replaceGlobal('URLSearchParams', BootstrapURLSearchParams);
    replaceGlobal('performance', bootstrapPerformance);

    evaluateBuiltin(urlBuiltinSource, false);
    evaluateBuiltin(perfHooksBuiltinSource, false);

    expect(globalThis.URL).not.toBe(BootstrapURL);
    expect(globalThis.URLSearchParams).not.toBe(BootstrapURLSearchParams);
    expect(globalThis.performance).not.toBe(bootstrapPerformance);
  });
});
