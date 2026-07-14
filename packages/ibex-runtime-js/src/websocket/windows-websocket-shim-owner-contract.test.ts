import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

interface WindowsWebSocketBridge {
  _handleOpen(protocol: string, extensions: string): void;
  _handleMessage(data: string | ArrayBuffer): void;
  _handleClose(code: number, reason: string, wasClean: boolean): void;
  _handleError(message: string): void;
  _handleBytesSent(bytesSent: number): void;
}

function embeddedWindowsWebSocketShim(): string {
  const source = readFileSync(
    new URL('../../../../src/engine/hermes_runtime_websocket.cc', import.meta.url),
    'utf8'
  );
  const match = source.match(
    /static const char\* windowsWebSocketShim = R"JS\(([\s\S]*?)\)JS";/
  );
  if (!match) throw new Error('Windows WebSocket shim not found');
  return match[1];
}

test('Windows shim keeps its selector private and preserves owner retries', () => {
  let bridge: WindowsWebSocketBridge | null = null;
  let sendError: Error | null = null;
  let closeError: Error | null = new Error('ERR_CAPABILITY_PRINCIPAL');
  let stateOwnerError: Error | null = null;
  const checkIds: number[] = [];
  const sentIds: number[] = [];
  const closeCalls: Array<{ id: number; code: number; reason: string }> = [];
  const messages: unknown[] = [];
  const sandbox: any = {
    WebSocket: undefined,
    __exactNetOwner: (action: string, stamp?: number) => {
      if (action === 'new') return 91;
      if (action !== 'assert' || stamp !== 91) throw new Error('invalid owner stamp');
      if (stateOwnerError) throw stateOwnerError;
    },
    __exactWsConnect: (
      _url: string,
      _protocols: string,
      callbackBridge: WindowsWebSocketBridge
    ) => {
      bridge = callbackBridge;
      return 73;
    },
    __exactWsSend: (id: number, data: unknown) => {
      if (data === undefined) {
        checkIds.push(id);
        if (sendError) throw sendError;
        return;
      }
      sentIds.push(id);
      if (sendError) throw sendError;
    },
    __exactWsClose: (id: number, code: number, reason: string) => {
      closeCalls.push({ id, code, reason });
      if (closeError) throw closeError;
    },
  };

  runInNewContext(embeddedWindowsWebSocketShim(), sandbox, {
    filename: 'windows-websocket-shim.js',
  });

  const ws = new sandbox.WebSocket('ws://example.test/socket');
  ws.onmessage = (event: { data: unknown }) => messages.push(event.data);
  bridge!._handleOpen('', '');
  expect(ws.readyState).toBe(sandbox.WebSocket.OPEN);
  bridge!._handleMessage('open message');
  expect(messages).toEqual(['open message']);
  expect('_socketId' in ws).toBe(false);
  expect('_handleOpen' in ws).toBe(false);
  expect('_handleClose' in ws).toBe(false);

  stateOwnerError = new Error('ERR_CAPABILITY_PRINCIPAL');
  expect(() => ws.url).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(() => ws.onmessage).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(() => {
    ws.onmessage = () => {};
  }).toThrow('ERR_CAPABILITY_PRINCIPAL');
  stateOwnerError = null;

  // Forged legacy fields cannot redirect the closure-private native selector
  // or drive the callback-owned lifecycle.
  ws._socketId = 999;
  ws._readyState = sandbox.WebSocket.CLOSED;
  expect(ws.readyState).toBe(sandbox.WebSocket.OPEN);

  // The shim captured the trusted host identities during installation.
  sandbox.__exactWsSend = () => {};
  sandbox.__exactWsClose = () => {};

  sendError = new Error('ERR_CAPABILITY_PRINCIPAL');
  expect(() => ws.send('denied')).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(ws.bufferedAmount).toBe(0);
  expect(checkIds).toEqual([73]);
  expect(sentIds).toEqual([]);

  sendError = null;
  ws.send('owner');
  expect(checkIds).toEqual([73, 73]);
  expect(sentIds).toEqual([73]);
  expect(ws.bufferedAmount).toBe(5);
  bridge!._handleBytesSent(5);
  expect(ws.bufferedAmount).toBe(0);

  expect(() => ws.close(1000, 'denied')).toThrow('ERR_CAPABILITY_PRINCIPAL');
  expect(ws.readyState).toBe(sandbox.WebSocket.OPEN);
  expect(closeCalls).toEqual([{ id: 73, code: 1000, reason: 'denied' }]);

  closeError = null;
  ws.close(1000, 'owner retry');
  expect(ws.readyState).toBe(sandbox.WebSocket.CLOSING);
  expect(closeCalls[1]).toEqual({ id: 73, code: 1000, reason: 'owner retry' });
  bridge!._handleMessage('queued after close');
  expect(messages).toEqual(['open message']);

  bridge!._handleClose(1000, 'owner retry', true);
  expect(ws.readyState).toBe(sandbox.WebSocket.CLOSED);
});
