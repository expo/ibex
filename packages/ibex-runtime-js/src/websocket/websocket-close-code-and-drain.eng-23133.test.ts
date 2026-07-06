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
// Entering the module graph through blob/Blob (as WebSocket.ts does) trips a
// pre-existing Blob -> streams -> clone -> File -> Blob circular-import TDZ
// error under bun's ESM evaluation (Blob.snapshot.test.ts fails the same way
// at HEAD). Loading clone first evaluates File/Blob in a safe order.
import '../clone';
import {
  getNativeWebSocketModule,
  setNativeWebSocketModule,
} from '../native/NativeModules';
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
    closeCalls: [] as Array<{ code?: number; reason?: string }>,
  };
  setNativeWebSocketModule({
    create: (_url: string, _protocols?: string[], instance?: any) => {
      state.bridge = instance as Bridge;
      return 1;
    },
    send: () => {},
    close: (_id: number, code?: number, reason?: string) => {
      state.closeCalls.push({ code, reason });
    },
  } as any);
  const restore = () => setNativeWebSocketModule(original as any);
  return { state, restore };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

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

    // Interleave so both tasks land in the same drain: the close path's outer
    // timer fires before the message drain timer, queueing [message, close].
    state.bridge!._handleClose(1000, 'bye', true);
    state.bridge!._handleMessage('m1');

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

test('M: throwing onmessage still lets WebSocketStream.closed settle', async () => {
  const { state, restore } = installFakeNative();
  const realConsoleError = console.error;
  try {
    const stream = new WebSocketStream('ws://example.test/socket');
    state.bridge!._handleOpen('', '');
    const opened = await withTimeout(stream.opened, 'stream.opened');

    // An app-level throwing handler on the underlying socket must not stall
    // stream teardown.
    (stream as any)._socket.onmessage = () => {
      throw new Error('app handler boom');
    };

    console.error = () => {};
    state.bridge!._handleClose(1000, '', true);
    state.bridge!._handleMessage('m1');

    const reader = opened.readable.getReader();
    const first = await withTimeout(reader.read(), 'first read');
    expect(first.value).toBe('m1');

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
