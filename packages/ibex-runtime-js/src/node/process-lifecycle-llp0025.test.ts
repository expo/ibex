// LLP 0022/0025 regressions: raw native bridge names are bootstrap-only, and
// process exit/beforeExit listeners are a diagnosed no-effect compatibility
// branch. Run with:
//   bun test packages/ibex-runtime-js/src/node/process-lifecycle-llp0025.test.ts

import { describe, expect, test } from 'bun:test';
import vm from 'node:vm';

const g = globalThis as Record<string, any>;
let freshImportOrdinal = 0;

async function freshProcessModule(): Promise<typeof import('./process.ts')> {
  freshImportOrdinal += 1;
  return import(`./process.ts?llp0025=${freshImportOrdinal}`);
}

function restoreGlobal(name: string, value: unknown): void {
  if (value === undefined) {
    delete g[name];
  } else {
    g[name] = value;
  }
}

describe('private lifecycle and stdin bridge captures', () => {
  test('process facade keeps bootstrap captures after globals are deleted or replaced', async () => {
    const previousStdinRead = g.__exactStdinRead;
    const previousExit = g.__exactExit;
    const readSizes: number[] = [];
    const exitCodes: Array<number | undefined> = [];

    try {
      g.__exactStdinRead = (size: number) => {
        readSizes.push(size);
        return new Uint8Array([0x41, 0x42]);
      };
      g.__exactExit = (code?: number) => {
        exitCodes.push(code);
      };

      const { process: ibexProcess } = await freshProcessModule();
      delete g.__exactStdinRead;
      delete g.__exactExit;

      expect(Array.from(ibexProcess.stdin.read(17))).toEqual([0x41, 0x42]);
      ibexProcess.exit(7);

      g.__exactStdinRead = () => {
        throw new Error('replacement stdin bridge must be unreachable');
      };
      g.__exactExit = () => {
        throw new Error('replacement lifecycle bridge must be unreachable');
      };

      expect(Array.from(ibexProcess.stdin.read(23))).toEqual([0x41, 0x42]);
      ibexProcess.exit();
      expect(readSizes).toEqual([17, 23]);
      expect(exitCodes).toEqual([7, undefined]);
    } finally {
      restoreGlobal('__exactStdinRead', previousStdinRead);
      restoreGlobal('__exactExit', previousExit);
    }
  });

  test('hand-authored bridge consumers contain only their trusted capture sites', async () => {
    const root = new URL('../../../../', import.meta.url);
    const cases: Array<[string, string, number]> = [
      ['packages/ibex-runtime-js/src/node/process.ts', '__exactStdinRead', 2],
      ['packages/ibex-runtime-js/src/node/process.ts', '__exactExit', 2],
      ['src/engine/bootstrap/stream-enhance.js', '__exactStdinRead', 2],
      ['src/engine/bootstrap/stream-enhance.js', '__exactExit', 2],
      ['src/engine/bootstrap/compat-polyfills.js', '__exactStdinRead', 2],
      ['src/builtins/process.js', '__exactStdinRead', 0],
    ];

    for (const [path, spelling, expectedCaptureReferences] of cases) {
      const source = await Bun.file(new URL(path, root)).text();
      expect(source.match(new RegExp(spelling, 'g'))?.length ?? 0).toBe(expectedCaptureReferences);
      expect(source).not.toMatch(new RegExp(`${spelling}\\s*\\(`));
    }
  });
});

describe('exit and beforeExit listener no-effect branch', () => {
  test('diagnosis remains observable once without a warning listener', async () => {
    const previousConsole = g.console;
    const messages: string[] = [];
    try {
      g.console = Object.assign(Object.create(previousConsole), {
        warn(message: unknown) {
          messages.push(String(message));
        },
      });
      const { process: ibexProcess } = await freshProcessModule();
      ibexProcess.on('exit', () => {});
      ibexProcess.once('beforeExit', () => {});

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(messages).toEqual([
        '[IBEX_LIFECYCLE_LISTENER_NO_EFFECT] process exit and beforeExit listeners are unsupported in Ibex and have no effect',
      ]);
    } finally {
      g.console = previousConsole;
    }
  });

  test('all aliases diagnose once, store nothing, expose nothing, and manual emit is closed', async () => {
    const { process: ibexProcess } = await freshProcessModule();
    const warnings: any[] = [];
    let lifecycleCalls = 0;
    let ordinaryCalls = 0;
    const lifecycleListener = () => {
      lifecycleCalls += 1;
    };
    const ordinaryListener = () => {
      ordinaryCalls += 1;
    };

    ibexProcess.on('warning', (warning: any) => warnings.push(warning));
    expect(ibexProcess.on('exit', lifecycleListener)).toBe(ibexProcess);
    expect(ibexProcess.addListener('beforeExit', lifecycleListener)).toBe(ibexProcess);
    expect(ibexProcess.once('exit', lifecycleListener)).toBe(ibexProcess);
    expect(ibexProcess.prependListener('beforeExit', lifecycleListener)).toBe(ibexProcess);
    expect(ibexProcess.prependOnceListener('exit', lifecycleListener)).toBe(ibexProcess);

    expect(ibexProcess.listeners('exit')).toEqual([]);
    expect(ibexProcess.rawListeners('beforeExit')).toEqual([]);
    expect(ibexProcess.listenerCount('exit')).toBe(0);
    expect(ibexProcess.listenerCount('beforeExit')).toBe(0);
    expect(ibexProcess.eventNames()).not.toContain('exit');
    expect(ibexProcess.eventNames()).not.toContain('beforeExit');
    expect(ibexProcess.emit('exit', 7)).toBe(false);
    expect(ibexProcess.emit('beforeExit', 0)).toBe(false);
    expect(lifecycleCalls).toBe(0);

    expect(ibexProcess.removeListener('exit', lifecycleListener)).toBe(ibexProcess);
    expect(ibexProcess.off('beforeExit', lifecycleListener)).toBe(ibexProcess);
    expect(ibexProcess.removeAllListeners('exit')).toBe(ibexProcess);
    expect(ibexProcess.removeAllListeners('beforeExit')).toBe(ibexProcess);

    ibexProcess.on('ordinary', ordinaryListener);
    expect(ibexProcess.emit('ordinary')).toBe(true);
    expect(ordinaryCalls).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(warnings).toHaveLength(1);
    expect(warnings[0].name).toBe('IbexLifecycleWarning');
    expect(warnings[0].code).toBe('IBEX_LIFECYCLE_LISTENER_NO_EFFECT');
  });

  test('stream bootstrap preserves the same bridge and listener contract', async () => {
    const source = await Bun.file(
      new URL('../../../../src/engine/bootstrap/stream-enhance.js', import.meta.url),
    ).text();
    const exitCodes: Array<number | undefined> = [];
    const warnings: any[] = [];
    const makeStream = (fd: number) => ({
      fd,
      isTTY: false,
      write() {
        return true;
      },
    });
    const processStub: any = {
      stdout: makeStream(1),
      stderr: makeStream(2),
      stdin: makeStream(0),
      env: {},
      versions: { node: '20.0.0' },
      version: 'v20.0.0',
      exitCode: 0,
      nextTick: queueMicrotask,
      abort() {
        throw new Error('process.abort() is not supported in Ibex runtime');
      },
    };
    const context: any = {
      process: processStub,
      setTimeout,
      clearTimeout,
      console,
      TextDecoder,
      Uint8Array,
      ArrayBuffer,
      Buffer,
      __exactStdinRead: (size: number) => new Uint8Array([size & 0xff]),
      __exactExit: (code?: number) => exitCodes.push(code),
    };
    context.globalThis = context;

    vm.runInNewContext(source, context);
    delete context.__exactStdinRead;
    delete context.__exactExit;

    expect(Array.from(processStub.stdin.read(19))).toEqual([19]);
    processStub.exit(12);
    expect(exitCodes).toEqual([12]);
    expect(() => processStub.abort()).toThrow('process.abort() is not supported');
    expect(exitCodes).toEqual([12]);

    processStub.on('warning', (warning: any) => warnings.push(warning));
    processStub.on('exit', () => {
      throw new Error('exit listener must never fire');
    });
    processStub.once('beforeExit', () => {
      throw new Error('beforeExit listener must never fire');
    });
    expect(processStub.listeners('exit')).toEqual([]);
    expect(processStub.rawListeners('beforeExit')).toEqual([]);
    expect(processStub.listenerCount('exit')).toBe(0);
    expect(processStub.emit('exit', 12)).toBe(false);

    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('IBEX_LIFECYCLE_LISTENER_NO_EFFECT');
  });
});
