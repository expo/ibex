// ENG-23133 — Three WebSocket/WebSocketStream fixes:
//
// H: A standard server close code other than 1000/1005/1006 (e.g. 1001
//    "going away", 1011 "internal error") made the WebSocketError constructor
//    throw inside WebSocketStream's close listener, so opened/closed never
//    settled and the stream hung forever. Wire-originated terminal errors now
//    go through a non-validating internal factory; the public constructor
//    still validates user-supplied codes.
// M: A throwing event handler aborted the event-queue drain loop, permanently
//    dropping later queued events (e.g. the 'close' behind a 'message').
// L: The constructor accepted URLs with embedded credentials; the spec
//    requires a SyntaxError.
//
// Run with: bun test packages/ibex-runtime-js/src/websocket

import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import {
  getNativeWebSocketModule,
  setNativeWebSocketModule,
} from '../native/NativeModules';
import { Blob as ExactBlob } from '../blob/Blob';
import { EventTarget } from '../events/EventTarget';
import {
  ReadableStream,
  ReadableStreamDefaultReader,
  WritableStreamDefaultWriter,
} from '../streams';
import { WebSocket } from './WebSocket';
import { WebSocketError, createWireWebSocketError } from './WebSocketError';
import { WebSocketStream } from './WebSocketStream';

interface Bridge {
  _handleOpen: (protocol: string, extensions: string) => void;
  _handleMessage: (data: string | ArrayBuffer) => void;
  _handleClose: (code: number, reason: string, wasClean: boolean) => void;
  _handleError: (message: string) => void;
  _handleBytesSent: (bytesSent: number) => void;
}

function installFakeNative() {
  const original = getNativeWebSocketModule();
  const state = {
    bridge: null as Bridge | null,
    checkCalls: [] as number[],
    checkError: null as Error | null,
    releaseCheckError: null as Error | null,
    stateOwnerError: null as Error | null,
    sendCalls: [] as Array<{ id: number; data: string | Uint8Array }>,
    closeCalls: [] as Array<{ id: number; code?: number; reason?: string }>,
    closeError: null as Error | null,
  };
  const nativeModule = {
    createOwner: () => 73,
    checkStateOwner: (_owner: unknown) => {
      if (state.stateOwnerError) {
        throw state.stateOwnerError;
      }
    },
    create: (_url: string, _protocols?: string[], instance?: any) => {
      state.bridge = instance as Bridge;
      return 1;
    },
    checkOwner: (id: number) => {
      state.checkCalls.push(id);
      if (state.checkError) {
        throw state.checkError;
      }
    },
    checkReleaseOwner: (id: number) => {
      state.checkCalls.push(id);
      if (state.releaseCheckError) {
        throw state.releaseCheckError;
      }
    },
    send: (id: number, data: string | Uint8Array) => {
      state.sendCalls.push({ id, data });
    },
    close: (id: number, code?: number, reason?: string) => {
      state.closeCalls.push({ id, code, reason });
      if (state.closeError) {
        throw state.closeError;
      }
    },
  } as any;
  setNativeWebSocketModule(nativeModule);
  const restore = () => setNativeWebSocketModule(original as any);
  return { state, nativeModule, restore };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

function createDeferredExactBlob(bytes: number[]): {
  blob: ExactBlob;
  resolve: (buffer: ArrayBuffer) => void;
} {
  let resolve!: (buffer: ArrayBuffer) => void;
  const bufferPromise = new Promise<ArrayBuffer>((res) => {
    resolve = res;
  });
  class DeferredExactBlob extends ExactBlob {
    override arrayBuffer(): Promise<ArrayBuffer> {
      return bufferPromise;
    }
  }
  return {
    blob: new DeferredExactBlob([new Uint8Array(bytes)]),
    resolve,
  };
}

class MismatchedExactBlob extends ExactBlob {
  override async arrayBuffer(): Promise<ArrayBuffer> {
    return new ArrayBuffer(this.size + 1);
  }
}

async function flushTimers(rounds: number): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await flush();
  }
}

async function withTimeout<T>(promise: Promise<T>, what: string, ms = 1000): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out waiting for ${what}`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

// ---------------------------------------------------------------------------
// H — wire close codes must settle the stream, not hang it
// ---------------------------------------------------------------------------

test('H: server close 1001 after open resolves stream.closed', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    await withTimeout(stream.opened, 'stream.opened');

    state.bridge!._handleClose(1001, 'going away', true);
    const closed = await withTimeout(stream.closed, 'stream.closed');
    expect(closed.closeCode).toBe(1001);
    expect(closed.reason).toBe('going away');
  } finally {
    restore();
  }
});

test('H: server close 1011 before open rejects opened and closed with a WebSocketError carrying the code', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleClose(1011, 'server error', false);

    const openedError = await withTimeout(
      stream.opened.then(() => null, (e) => e),
      'stream.opened rejection'
    );
    const closedError = await withTimeout(
      stream.closed.then(() => null, (e) => e),
      'stream.closed rejection'
    );
    expect(openedError).toBeInstanceOf(WebSocketError);
    expect(openedError.closeCode).toBe(1011);
    expect(openedError.reason).toBe('server error');
    expect(closedError).toBeInstanceOf(WebSocketError);
    expect(closedError.closeCode).toBe(1011);
  } finally {
    restore();
  }
});

test('H: unclean server close 1002 rejects stream.closed instead of hanging', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    await withTimeout(stream.opened, 'stream.opened');

    state.bridge!._handleClose(1002, 'protocol error', false);
    const closedError = await withTimeout(
      stream.closed.then(() => null, (e) => e),
      'stream.closed rejection'
    );
    expect(closedError).toBeInstanceOf(WebSocketError);
    expect(closedError.closeCode).toBe(1002);
  } finally {
    restore();
  }
});

test('H guard: public WebSocketError constructor still validates user-supplied codes', () => {
  // Wire factory accepts peer-controlled codes...
  const wireError = createWireWebSocketError('closed', 1001, 'going away');
  expect(wireError).toBeInstanceOf(WebSocketError);
  expect(wireError.closeCode).toBe(1001);

  // ...but user construction stays strict (including right after factory use,
  // i.e. the skip flag does not leak).
  for (const code of [999, 1001, 1002, 1011, 2999, 5000]) {
    let thrown: any = null;
    try {
      new WebSocketError('x', { closeCode: code });
    } catch (e) {
      thrown = e;
    }
    expect(thrown?.name).toBe('InvalidAccessError');
  }
  for (const code of [1000, 1005, 1006, 3000, 4999]) {
    expect(new WebSocketError('x', { closeCode: code }).closeCode).toBe(code);
  }

  let reasonError: any = null;
  try {
    new WebSocketError('x', { closeCode: 1000, reason: 'r'.repeat(124) });
  } catch (e) {
    reasonError = e;
  }
  expect(reasonError?.name).toBe('SyntaxError');
});

// ---------------------------------------------------------------------------
// M — a throwing handler must not abort the event-queue drain
// ---------------------------------------------------------------------------

test('M: throwing onmessage does not drop the queued close event', async () => {
  const { state, restore } = installFakeNative();
  const realConsoleError = console.error;
  let reportedErrors = 0;
  try {
    const ws = new WebSocket('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    await withTimeout(
      new Promise<void>((resolve) => ws.addEventListener('open', () => resolve(), { once: true })),
      'open event'
    );

    let onmessageCalls = 0;
    ws.onmessage = () => {
      onmessageCalls++;
      throw new Error('handler boom');
    };
    let listenerMessages = 0;
    ws.addEventListener('message', () => {
      listenerMessages++;
    });
    let closeEvent: any = null;
    ws.addEventListener('close', (event: any) => {
      closeEvent = event;
    });

    console.error = () => {
      reportedErrors++;
    };

    // Queue the message while OPEN, then close. A throwing message handler must
    // not prevent the later terminal task from running.
    state.bridge!._handleMessage('m1');
    state.bridge!._handleClose(1000, 'bye', true);

    await flushTimers(6);
    console.error = realConsoleError;

    expect(onmessageCalls).toBe(1);
    // dispatchEvent listeners still run even though onmessage threw.
    expect(listenerMessages).toBe(1);
    // The queued close event must survive the throwing handler.
    expect(closeEvent).not.toBeNull();
    expect(closeEvent.code).toBe(1000);
    expect(closeEvent.wasClean).toBe(true);
    expect(ws.readyState).toBe(WebSocket.CLOSED);
    // The exception was reported, not swallowed silently.
    expect(reportedErrors).toBeGreaterThanOrEqual(1);
  } finally {
    console.error = realConsoleError;
    restore();
  }
});

test('M: a forged WebSocketStream _socket cannot intercept messages or stall closed', async () => {
  const { state, restore } = installFakeNative();
  const realConsoleError = console.error;
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened');

    // The native socket is private. A legacy-looking own field is inert and
    // cannot intercept the real socket's event path.
    (stream as any)._socket = {
      onmessage: () => {
        throw new Error('forged handler boom');
      },
    };

    console.error = () => {};
    state.bridge!._handleMessage('m1');
    const reader = opened.readable.getReader();
    const first = await withTimeout(reader.read(), 'first read');
    expect(first.value).toBe('m1');

    state.bridge!._handleClose(1000, '', true);
    const closed = await withTimeout(stream.closed, 'stream.closed');
    expect(closed.closeCode).toBe(1000);
  } finally {
    console.error = realConsoleError;
    restore();
  }
});

// ---------------------------------------------------------------------------
// L — URLs with embedded credentials must throw SyntaxError
// ---------------------------------------------------------------------------

test('L: WebSocket constructor rejects URLs with embedded credentials', () => {
  const { restore } = installFakeNative();
  try {
    for (const url of [
      'ws://user:pass@example.test/',
      'ws://user@example.test/',
      'wss://user:pass@example.test/',
      'http://user:pass@example.test/', // scheme is upgraded to ws: first
    ]) {
      let thrown: any = null;
      try {
        new WebSocket(url);
      } catch (e) {
        thrown = e;
      }
      expect(thrown?.name).toBe('SyntaxError');
    }

    // Control: the same URL without credentials constructs fine.
    const ws = new WebSocket('ws://example.test/');
    expect(ws.url).toBe('ws://example.test/');
  } finally {
    restore();
  }
});

test('L: WebSocketStream propagates the credentials SyntaxError synchronously', () => {
  const { restore } = installFakeNative();
  try {
    let thrown: any = null;
    try {
      new WebSocketStream('ws://user:pass@example.test/');
    } catch (e) {
      thrown = e;
    }
    expect(thrown?.name).toBe('SyntaxError');
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// Retained-wrapper owner denial — close must remain retryable
// ---------------------------------------------------------------------------

test('retained WebSocket close denial preserves private selector and OPEN state for owner retry', async () => {
  const { state, restore } = installFakeNative();
  try {
    const ws = new WebSocket('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    expect(ws.readyState).toBe(WebSocket.OPEN);
    expect(Object.prototype.hasOwnProperty.call(ws, '_socketId')).toBe(false);

    // Forged legacy-looking fields and direct bridge-method calls cannot
    // redirect the native selector or drive the private state machine.
    (ws as any)._socketId = 999;
    (ws as any)._readyState = WebSocket.CLOSED;
    (ws as any)._sendQueue = [];
    expect(ws.readyState).toBe(WebSocket.OPEN);
    expect(() => (ws as any)._handleClose(1000, 'forged', true)).toThrow('Illegal invocation');
    expect(ws.readyState).toBe(WebSocket.OPEN);

    state.closeError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => ws.close(1000, 'denied')).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(ws.readyState).toBe(WebSocket.OPEN);
    expect(state.closeCalls).toEqual([{ id: 1, code: 1000, reason: 'denied' }]);

    state.closeError = null;
    ws.close(1000, 'owner retry');
    expect(ws.readyState).toBe(WebSocket.CLOSING);
    expect(state.closeCalls[1]).toEqual({ id: 1, code: 1000, reason: 'owner retry' });
    let lateMessages = 0;
    ws.onmessage = () => {
      lateMessages++;
    };
    state.bridge!._handleMessage('queued after close');
    await flushTimers(1);
    expect(lateMessages).toBe(0);
  } finally {
    restore();
  }
});

test('retained WebSocket cannot inspect listeners or subscribe to owner messages', async () => {
  const { state, restore } = installFakeNative();
  try {
    const ws = new WebSocket('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    await flushTimers(1);
    const ownerMessages: string[] = [];
    ws.onmessage = (event) => ownerMessages.push(`attribute:${event.data}`);
    EventTarget.prototype.addEventListener.call(
      ws,
      'message',
      ((event: any) => ownerMessages.push(`listener:${event.data}`)) as any
    );

    state.stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => ws.url).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => ws.onmessage).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      ws.onmessage = () => ownerMessages.push('foreign attribute');
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => EventTarget.prototype.addEventListener.call(
      ws,
      'message',
      (() => ownerMessages.push('foreign listener')) as any
    )).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => (ws as any)._listeners).toThrow('ERR_CAPABILITY_PRINCIPAL');
    let forgedEventReads = 0;
    expect(() => EventTarget.prototype.dispatchEvent.call(ws, {
      get type() {
        forgedEventReads++;
        return 'message';
      },
      data: 'forged',
    } as any)).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(forgedEventReads).toBe(0);

    let replacedDispatchCalls = 0;
    (ws as any).dispatchEvent = () => {
      replacedDispatchCalls++;
      return true;
    };
    state.stateOwnerError = null;
    state.bridge!._handleMessage('owner secret');
    await flushTimers(1);
    expect(ownerMessages).toEqual([
      'attribute:owner secret',
      'listener:owner secret',
    ]);
    expect(replacedDispatchCalls).toBe(0);
  } finally {
    restore();
  }
});

test('retained WebSocket send denial cannot append behind an owner Blob conversion', async () => {
  const { state, nativeModule, restore } = installFakeNative();
  try {
    const ws = new WebSocket('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    expect(ws.readyState).toBe(WebSocket.OPEN);

    const ownerBlob = createDeferredExactBlob([1, 2, 3]);
    ws.send(ownerBlob.blob as any);
    expect(ws.bufferedAmount).toBe(3);
    expect(state.sendCalls).toHaveLength(0);

    let foreignPropertyReads = 0;
    const foreignBlob = {
      get size() {
        foreignPropertyReads++;
        return 7;
      },
      get arrayBuffer() {
        foreignPropertyReads++;
        return async () => new ArrayBuffer(7);
      },
    };
    state.checkError = new Error('ERR_CAPABILITY_PRINCIPAL');
    state.releaseCheckError = state.checkError;

    // Neither patching the module object nor replacing the public registry
    // affects this already-created wrapper's closure-bound native methods.
    const launderedSelectors: number[] = [];
    nativeModule.checkOwner = () => {};
    nativeModule.checkReleaseOwner = () => {};
    nativeModule.send = (id: number) => {
      launderedSelectors.push(id);
    };
    setNativeWebSocketModule({
      createOwner: () => 999,
      checkStateOwner: () => {},
      create: () => 999,
      checkOwner: () => {},
      checkReleaseOwner: () => {},
      send: (id: number) => launderedSelectors.push(id),
      close: () => {},
    } as any);
    expect(() => WebSocket.prototype.send.call(ws, foreignBlob as any)).toThrow(
      'ERR_CAPABILITY_PRINCIPAL'
    );
    expect(foreignPropertyReads).toBe(0);
    expect(ws.bufferedAmount).toBe(3);
    expect(state.sendCalls).toHaveLength(0);
    expect(launderedSelectors).toHaveLength(0);

    // The closure-private queue key also blocks direct underscore-method
    // bypasses on the retained wrapper.
    expect(() => (ws as any)._queueSend(async () => {
      state.sendCalls.push({ id: 999, data: 'forged' });
    })).toThrow('Illegal invocation');

    state.checkError = null;
    state.releaseCheckError = null;
    ownerBlob.resolve(new Uint8Array([1, 2, 3]).buffer);
    await Promise.resolve();
    await Promise.resolve();
    expect(state.sendCalls).toHaveLength(1);
    expect(Array.from(state.sendCalls[0].data as Uint8Array)).toEqual([1, 2, 3]);
    state.bridge!._handleBytesSent(3);
    await Promise.resolve();

    ws.send('ok');
    await Promise.resolve();
    expect(state.sendCalls.map((call) => typeof call.data === 'string' ? call.data : 'binary')).toEqual([
      'binary',
      'ok',
    ]);
    state.bridge!._handleBytesSent(2);
    ws.close(1000, 'done');
    expect(state.closeCalls).toEqual([{ id: 1, code: 1000, reason: 'done' }]);
  } finally {
    restore();
  }
});

test('WebSocket accepts only branded Blobs and rolls back a mismatched conversion', async () => {
  const { state, restore } = installFakeNative();
  try {
    const ws = new WebSocket('ws://example.test/socket');
    state.bridge!._handleOpen('', '');

    let duckPropertyReads = 0;
    const duckBlob = {
      get size() {
        duckPropertyReads++;
        return 1;
      },
      get arrayBuffer() {
        duckPropertyReads++;
        return async () => new ArrayBuffer(1024 * 1024);
      },
    };
    ws.send(duckBlob as any);
    await Promise.resolve();
    expect(duckPropertyReads).toBe(0);
    expect(state.sendCalls).toHaveLength(1);
    expect(state.sendCalls[0].data).toBe('[object Object]');
    state.bridge!._handleBytesSent(15);
    await flushTimers(1);

    const mismatched = new MismatchedExactBlob([new Uint8Array([1, 2, 3])]);
    ws.send(mismatched as any);
    expect(ws.bufferedAmount).toBe(3);
    await flushTimers(1);
    expect(ws.bufferedAmount).toBe(0);
    expect(state.sendCalls).toHaveLength(1);
  } finally {
    restore();
  }
});

test('WebSocketStream rejects a zero-byte Blob size mismatch without a native send', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened');
    const writer = opened.writable.getWriter();

    const writeError = await withTimeout(
      writer.write(new MismatchedExactBlob([]) as any).then(
        () => null,
        (error) => error
      ),
      'mismatched Blob write rejection'
    );
    expect(writeError?.code).toBe('ERR_WEBSOCKET_BLOB_SIZE_MISMATCH');
    expect(state.sendCalls).toHaveLength(0);
  } finally {
    restore();
  }
});

test('WebSocketStream rejects foreign queued write/close/abort admission without poisoning owner work', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened');
    const writer = opened.writable.getWriter();

    const ownerBlob = createDeferredExactBlob([4, 5, 6]);
    const ownerWrite = writer.write(ownerBlob.blob as any);
    const desiredSizeWithOwnerWrite = writer.desiredSize;
    const writableInternals = opened.writable as any;
    expect(writableInternals._inFlightWriteRequest?.chunk).not.toBe(ownerBlob.blob);
    expect(
      writableInternals._writeRequests.some((request: any) => request.chunk === ownerBlob.blob)
    ).toBe(false);
    expect(
      writableInternals._queue.some((entry: any) => entry.chunk === ownerBlob.blob)
    ).toBe(false);

    state.checkError = new Error('ERR_CAPABILITY_PRINCIPAL');
    state.releaseCheckError = state.checkError;
    const foreignWriteError = await writer.write('foreign').then(
      () => null,
      (error) => error
    );
    expect(foreignWriteError?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(writer.desiredSize).toBe(desiredSizeWithOwnerWrite);

    const foreignCloseError = await writer.close().then(
      () => null,
      (error) => error
    );
    expect(foreignCloseError?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    const foreignAbortError = await writer.abort('foreign').then(
      () => null,
      (error) => error
    );
    expect(foreignAbortError?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(state.closeCalls).toHaveLength(0);

    state.checkError = null;
    state.releaseCheckError = null;
    ownerBlob.resolve(new Uint8Array([4, 5, 6]).buffer);
    await Promise.resolve();
    await Promise.resolve();
    expect(state.sendCalls).toHaveLength(1);
    state.bridge!._handleBytesSent(3);
    await withTimeout(ownerWrite, 'owner Blob write');

    const ownerWriteAfterDenial = writer.write('ok');
    await Promise.resolve();
    expect(state.sendCalls.map((call) => typeof call.data === 'string' ? call.data : 'binary')).toEqual([
      'binary',
      'ok',
    ]);
    state.bridge!._handleBytesSent(2);
    await withTimeout(ownerWriteAfterDenial, 'owner write after denial');

    // Positive send authority may be revoked while owner-only release must
    // remain available.
    state.checkError = new Error('Permission denied: __exactWsSend');
    const ownerClose = writer.close();
    await Promise.resolve();
    expect(state.closeCalls).toEqual([{ id: 1, code: 1005, reason: '' }]);
    state.bridge!._handleClose(1000, 'done', true);
    await withTimeout(ownerClose, 'owner writer close after send revocation');
    await withTimeout(stream.closed, 'stream.closed');
  } finally {
    restore();
  }
});

test('saved WebSocketStream sink cannot recover or convert an admitted owner chunk', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened');
    const writer = opened.writable.getWriter();
    let conversionReads = 0;
    const ownerChunk = {
      toString() {
        conversionReads++;
        return 'owner secret';
      },
    };

    const ownerWrite = writer.write(ownerChunk as any);
    expect(conversionReads).toBe(1);
    expect(state.sendCalls).toEqual([{ id: 1, data: 'owner secret' }]);
    const admittedEntry = (opened.writable as any)._inFlightWriteRequest?.chunk;
    expect(admittedEntry).toBeTruthy();
    expect(admittedEntry).not.toBe(ownerChunk);

    state.checkError = new Error('ERR_CAPABILITY_PRINCIPAL');
    const directWriteError = await (opened.writable as any)._writeAlgorithm(admittedEntry).then(
      () => null,
      (error: unknown) => error
    );
    expect((directWriteError as Error)?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(conversionReads).toBe(1);
    expect(state.sendCalls).toHaveLength(1);

    state.checkError = null;
    state.bridge!._handleBytesSent(new TextEncoder().encode('owner secret').byteLength);
    await withTimeout(ownerWrite, 'owner write after direct sink denial');
  } finally {
    restore();
  }
});

test('WebSocketStream forged fields and saved internal methods cannot poison owner retry', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    const privateFieldNames = [
      '_socket',
      '_readableController',
      '_readable',
      '_writable',
      '_openedDeferred',
      '_closedDeferred',
      '_openedSettled',
      '_closedSettled',
      '_connected',
      '_localCloseInitiated',
      '_closedDuringHandshake',
      '_ignoredTerminal',
      '_pendingWriteRequests',
      '_writableInvalidStateError',
      '_pendingWriteResolveTimer',
    ];
    for (const field of privateFieldNames) {
      expect(Object.prototype.hasOwnProperty.call(stream, field)).toBe(false);
    }

    let forgedSocketCalls = 0;
    Object.assign(stream as any, {
      _socket: {
        send: () => forgedSocketCalls++,
        close: () => forgedSocketCalls++,
      },
      _openedSettled: true,
      _closedSettled: true,
      _connected: false,
      _localCloseInitiated: true,
      _pendingWriteRequests: [{
        remaining: 0,
        resolve: () => forgedSocketCalls++,
        reject: () => forgedSocketCalls++,
      }],
    });

    const savedResolveClosed = WebSocketStream.prototype._resolveClosed;
    const savedHandleBytesSent = WebSocketStream.prototype._handleBytesSent;
    const savedInitiateClose = WebSocketStream.prototype._initiateClose;
    expect(() => savedResolveClosed.call(stream, { closeCode: 1000, reason: 'forged' })).toThrow(
      'Illegal invocation'
    );
    expect(() => savedHandleBytesSent.call(stream, 999)).toThrow('Illegal invocation');
    expect(() => savedInitiateClose.call(stream, 1000, 'forged')).toThrow('Illegal invocation');

    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened after field forgery');
    const writer = opened.writable.getWriter();

    let closeOptionReads = 0;
    state.releaseCheckError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => WebSocketStream.prototype.close.call(stream, {
      get closeCode() {
        closeOptionReads++;
        return 1000;
      },
      get reason() {
        closeOptionReads++;
        return 'foreign';
      },
    })).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(closeOptionReads).toBe(0);
    expect(state.closeCalls).toHaveLength(0);

    state.releaseCheckError = null;
    const ownerWrite = writer.write('ok');
    await Promise.resolve();
    expect(state.sendCalls).toEqual([{ id: 1, data: 'ok' }]);
    state.bridge!._handleBytesSent(2);
    await withTimeout(ownerWrite, 'owner write after field forgery');

    stream.close({ closeCode: 1000, reason: 'owner retry' });
    expect(state.closeCalls).toEqual([{ id: 1, code: 1000, reason: 'owner retry' }]);
    state.bridge!._handleClose(1000, 'owner retry', true);
    await withTimeout(stream.closed, 'stream.closed after field forgery');
    expect(forgedSocketCalls).toBe(0);
  } finally {
    restore();
  }
});

test('WebSocketStream readable cancel denial leaves owner cancellation retryable', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const { readable } = await withTimeout(stream.opened, 'stream.opened');

    state.releaseCheckError = new Error('ERR_CAPABILITY_PRINCIPAL');
    const foreignCancelError = await readable.cancel('foreign').then(
      () => null,
      (error) => error
    );
    expect(foreignCancelError?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(state.closeCalls).toHaveLength(0);

    state.releaseCheckError = null;
    const ownerCancel = readable.cancel('owner');
    await Promise.resolve();
    expect(state.closeCalls).toEqual([{ id: 1, code: 1005, reason: '' }]);
    state.bridge!._handleClose(1000, 'owner', true);
    await withTimeout(ownerCancel, 'owner readable cancellation retry');
    await withTimeout(stream.closed, 'stream.closed after readable cancellation');
  } finally {
    restore();
  }
});

test('retained WebSocketStream/readable/reader cannot inspect or consume owner messages', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    const ownerOpenedPromise = stream.opened;

    state.stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => stream.url).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => stream.opened).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => stream.closed).toThrow('ERR_CAPABILITY_PRINCIPAL');

    state.stateOwnerError = null;
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(ownerOpenedPromise, 'owner stream.opened');
    const readable = opened.readable;
    const reader = readable.getReader();
    expect(Object.getOwnPropertyDescriptor(reader, '_initializeClosedPromise')?.enumerable)
      .toBe(false);
    expect(Object.getOwnPropertyDescriptor(reader, '_processReadRequests')?.enumerable)
      .toBe(false);

    state.bridge!._handleMessage('owner secret');
    await flushTimers(2);

    const savedGetReader = ReadableStream.prototype.getReader;
    const savedRead = ReadableStreamDefaultReader.prototype.read;
    state.stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');

    // The authority-bearing stream projects controller and lifecycle fields
    // through owner checks. Its descriptor never exposes the real controller,
    // whose compatibility queue contains only opaque identities in any case.
    expect(() => (readable as any)._controller).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => (readable as any)._state).toThrow('ERR_CAPABILITY_PRINCIPAL');
    const controllerDescriptor = Object.getOwnPropertyDescriptor(readable, '_controller');
    expect(controllerDescriptor?.value).toBeUndefined();
    expect(typeof controllerDescriptor?.get).toBe('function');
    expect(() => controllerDescriptor!.get!.call(readable)).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      (readable as any)._state = 'closed';
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      (readable as any)._cancelStream = () => Promise.resolve();
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');

    // Saved base methods authenticate before lock/queue/disturbed state. The
    // retained reader's stream pointer and request arrays are projections too,
    // so they cannot be swapped or seeded with a payload-stealing resolver.
    expect(() => savedGetReader.call(readable)).toThrow('ERR_CAPABILITY_PRINCIPAL');
    const foreignReadError = await savedRead.call(reader).then(
      () => null,
      (error) => error
    );
    expect(foreignReadError?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(() => (reader as any)._readRequests).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      (reader as any)._stream = {};
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      (reader as any)._processReadRequests = () => {};
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => reader.releaseLock()).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => readable.values({ preventCancel: true })).toThrow('ERR_CAPABILITY_PRINCIPAL');

    state.stateOwnerError = null;
    const first = await withTimeout(savedRead.call(reader), 'owner read after denial');
    expect(first).toEqual({ done: false, value: 'owner secret' });
    reader.releaseLock();

    // Async iteration routes through the same captured getReader/read gates.
    state.bridge!._handleMessage('owner iterator secret');
    await flushTimers(2);
    state.stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => readable.values({ preventCancel: true })).toThrow('ERR_CAPABILITY_PRINCIPAL');

    state.stateOwnerError = null;
    const iterator = readable.values({ preventCancel: true });
    expect(await withTimeout(iterator.next(), 'owner async iterator read')).toEqual({
      done: false,
      value: 'owner iterator secret',
    });
    await iterator.return?.();

    // The wrapper-lifetime stamp (rather than a live OPEN/send check) keeps an
    // already-buffered peer message readable by its owner after clean close.
    state.bridge!._handleMessage('owner post-close buffer');
    await flushTimers(2);
    stream.close({ closeCode: 1000, reason: 'owner' });
    state.bridge!._handleClose(1000, 'owner', true);
    const ownerClosedPromise = stream.closed;
    await withTimeout(ownerClosedPromise, 'owner stream.closed');
    const postCloseReader = readable.getReader();
    expect(await postCloseReader.read()).toEqual({
      done: false,
      value: 'owner post-close buffer',
    });
    expect(await postCloseReader.read()).toEqual({ done: true, value: undefined });
    postCloseReader.releaseLock();
    state.stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => stream.closed).toThrow('ERR_CAPABILITY_PRINCIPAL');
    state.stateOwnerError = null;
    expect(await stream.closed).toEqual({ closeCode: 1000, reason: 'owner' });
  } finally {
    restore();
  }
});

test('retained WebSocketStream writable/writer fields cannot poison owner retry', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const { writable } = await withTimeout(stream.opened, 'stream.opened');
    const writer = writable.getWriter();
    const savedWrite = WritableStreamDefaultWriter.prototype.write;

    state.stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
    for (const field of ['_state', '_queue', '_writer', '_writeAlgorithm']) {
      expect(() => (writable as any)[field]).toThrow('ERR_CAPABILITY_PRINCIPAL');
    }
    expect(() => {
      (writable as any)._state = 'closed';
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      (writable as any)._writeChunk = () => Promise.resolve();
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => (writer as any)._stream).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => {
      (writer as any)._stream = {};
    }).toThrow('ERR_CAPABILITY_PRINCIPAL');
    expect(() => (writer as any)._readyPromise).toThrow('ERR_CAPABILITY_PRINCIPAL');

    const foreignWriteError = await savedWrite.call(writer, 'foreign').then(
      () => null,
      (error) => error
    );
    expect(foreignWriteError?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(state.sendCalls).toHaveLength(0);

    state.stateOwnerError = null;
    const ownerWrite = savedWrite.call(writer, 'owner retry');
    await Promise.resolve();
    expect(state.sendCalls).toEqual([{ id: 1, data: 'owner retry' }]);
    state.bridge!._handleBytesSent(new TextEncoder().encode('owner retry').byteLength);
    await withTimeout(ownerWrite, 'owner write after field denial');

    const ownerClose = writer.close();
    await Promise.resolve();
    expect(state.closeCalls).toEqual([{ id: 1, code: 1005, reason: '' }]);
    state.bridge!._handleClose(1000, 'owner', true);
    await withTimeout(ownerClose, 'owner close after field denial');
  } finally {
    restore();
  }
});

test('saved writable close algorithm denial cannot consume the owner close admission', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened');
    const writer = opened.writable.getWriter();

    const pendingBlob = createDeferredExactBlob([1]);
    const ownerWrite = writer.write(pendingBlob.blob as any);
    const ownerClose = writer.close();

    // close() was admitted synchronously but is queued behind the Blob write.
    // A retained caller invoking the saved sink algorithm must neither close
    // the socket nor burn that private admission when the native owner check
    // rejects it.
    state.closeError = new Error('ERR_CAPABILITY_PRINCIPAL');
    const directCloseError = await (opened.writable as any)._closeAlgorithm().then(
      () => null,
      (error: unknown) => error
    );
    expect((directCloseError as Error)?.message).toContain('ERR_CAPABILITY_PRINCIPAL');
    expect(state.closeCalls).toEqual([{ id: 1, code: 1005, reason: '' }]);

    state.closeError = null;
    pendingBlob.resolve(new Uint8Array([1]).buffer);
    await Promise.resolve();
    await Promise.resolve();
    state.bridge!._handleBytesSent(1);
    await withTimeout(ownerWrite, 'owner write before queued close');
    await flushTimers(1);
    expect(state.closeCalls).toEqual([
      { id: 1, code: 1005, reason: '' },
      { id: 1, code: 1005, reason: '' },
    ]);
    state.bridge!._handleClose(1000, 'owner', true);
    await withTimeout(ownerClose, 'owner close after direct denial');
  } finally {
    restore();
  }
});

test('retained WebSocketStream close denial does not settle or poison the owner stream', async () => {
  const { state, restore } = installFakeNative();
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    await withTimeout(stream.opened, 'stream.opened');

    state.closeError = new Error('ERR_CAPABILITY_PRINCIPAL');
    expect(() => stream.close({ closeCode: 1000, reason: 'denied' })).toThrow(
      'ERR_CAPABILITY_PRINCIPAL'
    );
    expect(state.closeCalls).toEqual([{ id: 1, code: 1000, reason: 'denied' }]);

    state.closeError = null;
    stream.close({ closeCode: 1000, reason: 'owner retry' });
    expect(state.closeCalls[1]).toEqual({ id: 1, code: 1000, reason: 'owner retry' });
    state.bridge!._handleClose(1000, 'owner retry', true);
    const closed = await withTimeout(stream.closed, 'stream.closed');
    expect(closed).toEqual({ closeCode: 1000, reason: 'owner retry' });
    expect(state.closeCalls.map((call) => call.id)).toEqual([1, 1]);
  } finally {
    restore();
  }
});

test('minimal runtime ExactWebSocket keeps id private and retries after native owner denial', () => {
  const runtimeSource = readFileSync(
    new URL('../../../../src/bin/ibex/runtime.rs', import.meta.url),
    'utf8'
  );
  const bootstrapMatch = runtimeSource.match(
    /const WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP: &str = r#"([\s\S]*?)"#;/
  );
  expect(bootstrapMatch).not.toBeNull();

  let bridge: Bridge | null = null;
  let closeError: Error | null = new Error('ERR_CAPABILITY_PRINCIPAL');
  let sendError: Error | null = null;
  let stateOwnerError: Error | null = null;
  const checkIds: number[] = [];
  const sendIds: number[] = [];
  const closeIds: number[] = [];
  const messages: unknown[] = [];
  const sandbox: any = {
    console,
    setTimeout,
    clearTimeout,
    queueMicrotask,
    __exactNetOwner: (action: string, stamp?: number) => {
      if (action === 'new') return 77;
      if (action !== 'assert' || stamp !== 77) throw new Error('invalid owner stamp');
      if (stateOwnerError) throw stateOwnerError;
    },
    __exactWsConnect: (_url: string, _protocols: string, callbackBridge: Bridge) => {
      bridge = callbackBridge;
      return 41;
    },
    __exactWsSend: (id: number, data: unknown) => {
      if (data === undefined) {
        checkIds.push(id);
        if (sendError) throw sendError;
        return;
      }
      sendIds.push(id);
      if (sendError) throw sendError;
    },
    __exactWsClose: (id: number) => {
      closeIds.push(id);
      if (closeError) throw closeError;
    },
  };
  runInNewContext(bootstrapMatch![1], sandbox, { filename: 'windows-minimal-runtime.js' });

  const ws = new sandbox.WebSocket('ws://example.test/socket');
  ws.onmessage = (event: { data: unknown }) => messages.push(event.data);
  bridge!._handleOpen('', '');
  expect(ws.readyState).toBe(sandbox.WebSocket.OPEN);
  bridge!._handleMessage('open message');
  expect(messages).toEqual(['open message']);
  expect(Object.prototype.hasOwnProperty.call(ws, '__id')).toBe(false);

  stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
  expect(() => ws.addEventListener('message', () => {})).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(() => ws.onmessage).toThrow('ERR_CAPABILITY_PRINCIPAL');
  stateOwnerError = null;

  ws.__id = 999;
  expect(() => {
    ws.readyState = sandbox.WebSocket.CLOSED;
  }).toThrow();
  expect(ws.readyState).toBe(sandbox.WebSocket.OPEN);

  sandbox.__exactWsSend = () => {};
  sandbox.__exactWsClose = () => {};
  sendError = new Error('ERR_CAPABILITY_PRINCIPAL');
  expect(() => ws.send('denied')).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(ws.bufferedAmount).toBe(0);
  expect(checkIds).toEqual([41]);
  expect(sendIds).toEqual([]);
  sendError = null;
  ws.send('owner');
  expect(checkIds).toEqual([41, 41]);
  expect(sendIds).toEqual([41]);

  expect(() => ws.close(1000, 'denied')).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(ws.readyState).toBe(sandbox.WebSocket.OPEN);

  closeError = null;
  ws.close(1000, 'owner retry');
  expect(ws.readyState).toBe(sandbox.WebSocket.CLOSING);
  expect(closeIds).toEqual([41, 41]);
  bridge!._handleMessage('queued after close');
  expect(messages).toEqual(['open message']);
});
