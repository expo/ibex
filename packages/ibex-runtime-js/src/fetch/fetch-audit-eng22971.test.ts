// ENG-22971 — correctness/perf audit of ibex fetch code. Covers five findings:
//   1. A redirect that preserves a ReadableStream (source-null) request body
//      must fail with a network error instead of replaying a partial/duplicated
//      body.
//   2. A method-rewriting redirect (301/302 POST -> GET, 303 -> GET) must drop
//      the request-body entity headers (Content-Type et al.) along with the body.
//   3. An aborted fetch signal must reject body consumption (and cancel an
//      in-flight download) instead of resolving with the full body.
//   4. Response.clone() must not share its internal ArrayBuffer, and each body
//      consumption must yield a fresh ArrayBuffer (mutating one read must not
//      corrupt a clone's later read).
//   5. The raw HTTP/1.1 socket transport must parse responses incrementally
//      (O(n)) rather than re-concatenating the whole growing buffer per chunk.
// Run with: bun test src/fetch/fetch-audit-eng22971.test.ts

import { beforeAll, describe, expect, test } from 'bun:test';
import { fetch, setNativeFetchModule, executeRawHttpSocketFetchHop } from './fetch.ts';
import { Response } from './Response.ts';
import { enableTestMode } from '../security/Capabilities.ts';
import type { NativeRequestInit, NativeResponse } from './types.ts';

beforeAll(() => {
  enableTestMode(['*']);
});

interface RecordedCall {
  url: string;
  method: string;
  headers: [string, string][];
  body: Uint8Array | null;
}

function installMockNative(responses: NativeResponse[]): RecordedCall[] {
  const calls: RecordedCall[] = [];
  setNativeFetchModule({
    async fetch(url: string, init: NativeRequestInit, body: Uint8Array | null) {
      calls.push({
        url,
        method: init.method,
        headers: init.headers.map(([n, v]) => [n.toLowerCase(), v] as [string, string]),
        body,
      });
      const next = responses.shift();
      if (!next) {
        throw new Error('mock native fetch: no response queued');
      }
      return next;
    },
  } as any);
  return calls;
}

function nativeResponse(partial: Partial<NativeResponse> & { status: number }): NativeResponse {
  return {
    statusText: '',
    headers: [],
    url: 'http://redirect.test/',
    redirected: false,
    body: null,
    ...partial,
  };
}

function headerPresent(headers: [string, string][], name: string): boolean {
  return headers.some(([n]) => n === name.toLowerCase());
}

async function expectRejectsWithName(promise: Promise<unknown>, name: string) {
  try {
    await promise;
  } catch (error) {
    expect(error).toMatchObject({ name });
    return;
  }
  throw new Error(`expected promise to reject with ${name}`);
}

describe('#1 streaming request body cannot be replayed across a redirect', () => {
  test('307 preserving a ReadableStream body rejects with TypeError and does not re-send', async () => {
    const calls = installMockNative([
      nativeResponse({ status: 307, headers: [['location', '/next']] }),
      // Should never be reached — the redirect must fail first.
      nativeResponse({ status: 200, body: new TextEncoder().encode('unreached').buffer }),
    ]);

    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array([1, 2, 3]));
        c.close();
      },
    });

    await expect(
      fetch('http://redirect.test/start', { method: 'POST', body: stream, duplex: 'half' } as any)
    ).rejects.toThrow(TypeError);

    // Only the first hop ran; the body was not replayed to the redirect target.
    expect(calls.length).toBe(1);
  });
});

describe('#2 method-rewriting redirect drops the request body and its entity headers', () => {
  test('303 POST -> GET sends no body and no Content-Type on the follow-up', async () => {
    const calls = installMockNative([
      nativeResponse({ status: 303, headers: [['location', '/next']] }),
      nativeResponse({ status: 200, body: new TextEncoder().encode('ok').buffer }),
    ]);

    const res = await fetch('http://redirect.test/start', {
      method: 'POST',
      body: JSON.stringify({ a: 1 }),
      headers: { 'content-type': 'application/json' },
    });

    expect(await res.text()).toBe('ok');
    expect(calls.length).toBe(2);

    const followup = calls[1];
    expect(followup.method).toBe('GET');
    expect(followup.body).toBeNull();
    expect(headerPresent(followup.headers, 'content-type')).toBe(false);
    // Sanity: the original POST did carry the Content-Type.
    expect(headerPresent(calls[0].headers, 'content-type')).toBe(true);
  });
});

describe('#3 abort cancels body reads', () => {
  test('reading an already-aborted response rejects with AbortError (buffered body)', async () => {
    const res = new Response('hello world');
    const controller = new AbortController();
    res._signal = controller.signal;
    controller.abort();

    await expectRejectsWithName(res.text(), 'AbortError');
  });

  test('aborting mid-read rejects a streaming body instead of hanging/resolving', async () => {
    // A body stream that never produces data — before the fix, reading it with
    // no signal threaded through would never settle.
    const pending = new ReadableStream<Uint8Array>({ pull() { return new Promise<void>(() => {}); } });
    const res = new Response(pending);
    const controller = new AbortController();
    res._signal = controller.signal;

    const reading = res.text();
    await new Promise((r) => setTimeout(r, 10));
    controller.abort();

    await expectRejectsWithName(reading, 'AbortError');
  });
});

describe('#4 clone() and arrayBuffer() do not share the internal buffer', () => {
  test('mutating one read does not corrupt a clone read', async () => {
    const res = new Response(new Uint8Array([1, 2, 3, 4]));
    const clone = res.clone();

    const first = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(first)).toEqual([1, 2, 3, 4]);
    first[0] = 99; // caller mutates the buffer it received

    const cloneRead = new Uint8Array(await clone.arrayBuffer());
    expect(Array.from(cloneRead)).toEqual([1, 2, 3, 4]);
  });

  test('each consumption yields an independent ArrayBuffer', async () => {
    const a = new Response(new Uint8Array([5, 6, 7]));
    const b = a.clone();
    const bufA = await a.arrayBuffer();
    const bufB = await b.arrayBuffer();
    expect(bufA).not.toBe(bufB);
    new Uint8Array(bufA)[1] = 0;
    expect(Array.from(new Uint8Array(bufB))).toEqual([5, 6, 7]);
  });
});

describe('#5 raw HTTP/1.1 socket transport parses incrementally', () => {
  function makeFakeSocket() {
    const listeners: Record<string, Array<(...args: any[]) => void>> = {};
    return {
      on(event: string, fn: (...args: any[]) => void) {
        (listeners[event] ||= []).push(fn);
        return this;
      },
      once(event: string, fn: (...args: any[]) => void) {
        (listeners[event] ||= []).push(fn);
        return this;
      },
      removeAllListeners(event?: string) {
        if (event) delete listeners[event];
        else for (const k of Object.keys(listeners)) delete listeners[k];
        return this;
      },
      write() { return true; },
      end() { return this; },
      destroy() { return this; },
      setNoDelay() { return this; },
      unref() { return this; },
      emit(event: string, ...args: any[]) {
        (listeners[event] || []).slice().forEach((fn) => fn(...args));
      },
    };
  }

  function drive(rawResponse: string, chunkSize: number, method = 'GET'): Promise<NativeResponse> {
    const socket = makeFakeSocket();
    const fakeRequire = (spec: string) => {
      if (spec === 'node:net') {
        return { createConnection: () => socket };
      }
      throw new Error(`unexpected require: ${spec}`);
    };
    const init: NativeRequestInit = {
      method,
      headers: [],
      credentials: 'same-origin',
      redirect: 'follow',
      decompress: true,
    };
    const promise = executeRawHttpSocketFetchHop(
      'http://socket.test/x',
      init,
      [],
      null,
      fakeRequire as any,
      null
    );
    // Listeners are registered synchronously in the promise executor.
    socket.emit('connect');
    const bytes = new TextEncoder().encode(rawResponse);
    for (let i = 0; i < bytes.length; i += chunkSize) {
      socket.emit('data', bytes.subarray(i, i + chunkSize));
    }
    socket.emit('end');
    return promise;
  }

  function decodeBody(res: NativeResponse): string {
    return res.body ? new TextDecoder().decode(new Uint8Array(res.body)) : '';
  }

  test('content-length body split across many tiny chunks', async () => {
    const payload = '0123456789ABCDEF';
    const raw = `HTTP/1.1 200 OK\r\nContent-Length: ${payload.length}\r\n\r\n${payload}`;
    const res = await drive(raw, 3);
    expect(res.status).toBe(200);
    expect(decodeBody(res)).toBe(payload);
  });

  test('content-length stops exactly at the declared length (ignores trailing bytes)', async () => {
    const raw = `HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLOEXTRA`;
    const res = await drive(raw, 2);
    expect(decodeBody(res)).toBe('HELLO');
  });

  test('chunked body split across tiny chunks', async () => {
    const raw =
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' +
      '5\r\nHello\r\n' +
      '6\r\n World\r\n' +
      '0\r\n\r\n';
    const res = await drive(raw, 4);
    expect(res.status).toBe(200);
    expect(decodeBody(res)).toBe('Hello World');
  });

  test('large content-length body reassembles correctly across 1-byte feeds', async () => {
    let payload = '';
    for (let i = 0; i < 500; i++) payload += String.fromCharCode(97 + (i % 26));
    const raw = `HTTP/1.1 200 OK\r\nContent-Length: ${payload.length}\r\n\r\n${payload}`;
    const res = await drive(raw, 1);
    expect(decodeBody(res)).toBe(payload);
  });

  test('connection-close delimited body', async () => {
    const raw = 'HTTP/1.1 200 OK\r\n\r\nsome body bytes';
    const res = await drive(raw, 5);
    expect(decodeBody(res)).toBe('some body bytes');
  });
});
