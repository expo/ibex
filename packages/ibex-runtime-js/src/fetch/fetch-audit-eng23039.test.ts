// ENG-23039 — fetch streaming/abort/redirect gaps found in the round-2
// perf/correctness audit (related to ENG-22971). Covers three findings:
//   1. The socket response-body stream applied no backpressure: it forwarded
//      every 'data' chunk regardless of the ReadableStream's internal queue
//      size, so a slow consumer let the whole response buffer unbounded.
//      Fix: pause the source when desiredSize <= 0, resume() from pull().
//   2. The native streaming body only reacted to abort during the headers
//      race; once headers resolved, nothing stopped an in-flight download on
//      a post-headers abort(). Fix: wire a signal 'abort' listener directly
//      on the streaming body (mirroring the existing socket-path listener).
//   3. A method-rewriting redirect (301/302 POST -> GET, 303 -> GET) stripped
//      Content-Type/-Encoding/-Language/-Location but not Content-Length, so
//      a caller-supplied Content-Length survived onto a now-bodyless request.
// Run with: bun test src/fetch/fetch-audit-eng23039.test.ts

import { beforeAll, describe, expect, test } from 'bun:test';
import {
  fetch,
  setNativeFetchModule,
  createSocketResponseBodyStream,
  REQUEST_BODY_HEADERS,
} from './fetch.ts';
import { enableTestMode } from '../security/Capabilities.ts';
import type { NativeRequestInit, NativeResponse, NativeStreamingResponse } from './types.ts';

beforeAll(() => {
  enableTestMode(['*']);
});

function headerPresent(headers: [string, string][], name: string): boolean {
  return headers.some(([n]) => n === name.toLowerCase());
}

describe('#1 socket response body backpressure', () => {
  function makeFakeSourceStream() {
    const listeners: Record<string, Array<(...args: any[]) => void>> = {};
    let paused = false;
    return {
      on(event: string, fn: (...args: any[]) => void) {
        (listeners[event] ||= []).push(fn);
        return this;
      },
      pause() {
        paused = true;
      },
      resume() {
        paused = false;
      },
      destroy() {},
      emit(event: string, ...args: any[]) {
        (listeners[event] || []).slice().forEach((fn) => fn(...args));
      },
      get paused() {
        return paused;
      },
    };
  }

  test('the source is paused once the internal queue is full and resumed on pull', async () => {
    const source = makeFakeSourceStream();
    const stream = createSocketResponseBodyStream(
      source as any,
      [],
      false,
      (spec: string) => {
        throw new Error(`unexpected require: ${spec}`);
      },
      null
    );
    const reader = stream.getReader();

    // Default queuing strategy: highWaterMark 1. A single enqueued chunk
    // fills the queue (desiredSize 0), so the source must be paused —
    // before the fix, chunks were forwarded unconditionally regardless of
    // consumer demand.
    source.emit('data', new Uint8Array([1, 2, 3]));
    expect(source.paused).toBe(true);

    const { value } = await reader.read();
    expect(Array.from(value!)).toEqual([1, 2, 3]);

    // Draining the queue must resume the source via pull().
    await new Promise((r) => setTimeout(r, 0));
    expect(source.paused).toBe(false);
  });
});

describe('#2 native streaming body cancels + rejects on a post-headers abort', () => {
  test('aborting after headers resolve cancels the native download and rejects the next read', async () => {
    let cancelCalled = false;
    let deliverChunk!: (chunk: Uint8Array) => void;

    setNativeFetchModule({
      fetchStreaming(
        _url: string,
        _init: NativeRequestInit,
        _body: Uint8Array | null,
        onHeaders: (r: NativeStreamingResponse) => void,
        onData: (chunk: Uint8Array) => void,
        _onComplete: () => void,
        _onError: (e: Error) => void
      ) {
        deliverChunk = onData;
        queueMicrotask(() =>
          onHeaders({ status: 200, statusText: 'OK', headers: [], url: 'http://streaming.test/', redirected: false })
        );
        return () => {
          cancelCalled = true;
        };
      },
    } as any);

    const controller = new AbortController();
    const res = await fetch('http://streaming.test/data', { signal: controller.signal });
    const reader = res.body!.getReader();

    deliverChunk(new Uint8Array([1, 2, 3]));
    const first = await reader.read();
    expect(Array.from(first.value!)).toEqual([1, 2, 3]);

    expect(cancelCalled).toBe(false);
    controller.abort();

    await expect(reader.read()).rejects.toMatchObject({ name: 'AbortError' });
    // Before the fix, nothing stopped the in-flight native download: the
    // cancel callback returned by fetchStreaming() was never invoked once
    // headers had already resolved.
    expect(cancelCalled).toBe(true);
  });
});

describe('#3 content-length is stripped on a method-rewriting redirect', () => {
  // Content-Length is a forbidden request header per the Fetch spec, and
  // Ibex's own Headers guard enforces that (confirmed: `fetch()` with a
  // caller-supplied `content-length` header never puts it on the wire in the
  // first place), so the fix can't be driven end-to-end through the public
  // fetch()/Headers surface — it defends a lower layer where a Content-Length
  // could otherwise be injected into the outgoing native headers. Assert the
  // fix directly against the stripping list.
  test('REQUEST_BODY_HEADERS includes content-length alongside the other entity headers', () => {
    expect(REQUEST_BODY_HEADERS).toEqual(
      expect.arrayContaining(['content-encoding', 'content-language', 'content-location', 'content-type', 'content-length'])
    );
  });

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

  test('302 POST -> GET still drops the other body entity headers (regression guard)', async () => {
    const calls: NativeRequestInit[] = [];
    const bodies: Array<Uint8Array | null> = [];
    setNativeFetchModule({
      async fetch(_url: string, init: NativeRequestInit, body: Uint8Array | null) {
        calls.push(init);
        bodies.push(body);
        if (calls.length === 1) {
          return nativeResponse({ status: 302, headers: [['location', '/next']] });
        }
        return nativeResponse({ status: 200, body: new TextEncoder().encode('ok').buffer });
      },
    } as any);

    const res = await fetch('http://redirect.test/start', {
      method: 'POST',
      body: '{}',
      headers: { 'content-type': 'application/json' },
    });

    expect(await res.text()).toBe('ok');
    expect(calls.length).toBe(2);

    const followup = calls[1];
    expect(followup.method).toBe('GET');
    expect(bodies[1]).toBeNull();
    expect(headerPresent(followup.headers, 'content-type')).toBe(false);
    expect(headerPresent(calls[0].headers, 'content-type')).toBe(true);
  });
});
