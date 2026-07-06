// ENG-23040 #1, #2 — Response/Request.clone() and Response's body-stream
// materialization, found in the round-2 perf/correctness audit (related to
// ENG-22972/22973/22977). Covers:
//   1. clone() gated on the raw `_bodyUsed` field instead of the `bodyUsed`
//      getter, so a body disturbed via a reader (read then releaseLock(),
//      never setting `_bodyUsed`) passed the guard and tee()'d an
//      already-drained stream. Fix: gate on the `bodyUsed` getter.
//   2. Response's constructor/fromNative eagerly built `_body` (a full byte
//      copy via createReadableStreamFromUint8Array) even though
//      arrayBuffer()/text()/json() read `_bodyBuffer` directly and never
//      touch it — pure waste unless the caller reads `.body`. Fix: make
//      `Response.body` a lazy getter (mirroring `Request.body`) that only
//      builds the stream from `_bodyBuffer` on first access.
// Run with: bun test src/fetch/fetch-audit-eng23040.test.ts

import { describe, expect, test } from 'bun:test';
import { Response } from './Response.ts';
import { Request } from './Request.ts';

describe('#1 clone() gates on bodyUsed (disturbed), not just the raw _bodyUsed flag', () => {
  test('Response.clone() throws once the body has been disturbed via a released reader', async () => {
    const res = new Response(
      new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new Uint8Array([1, 2, 3]));
          c.close();
        },
      })
    );
    const reader = res.body!.getReader();
    await reader.read();
    reader.releaseLock(); // unlocked again, but now disturbed

    expect(res.bodyUsed).toBe(true);
    expect(() => res.clone()).toThrow(TypeError);
  });

  test('Request.clone() throws once the body has been disturbed via a released reader', async () => {
    const req = new Request('http://example.test/', {
      method: 'POST',
      body: new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new Uint8Array([1, 2, 3]));
          c.close();
        },
      }),
      duplex: 'half',
    } as any);
    const reader = req.body!.getReader();
    await reader.read();
    reader.releaseLock();

    expect(req.bodyUsed).toBe(true);
    expect(() => req.clone()).toThrow(TypeError);
  });

  test('Response.clone() still succeeds for an untouched body', async () => {
    const res = new Response('hello');
    const clone = res.clone();
    expect(await clone.text()).toBe('hello');
    expect(await res.text()).toBe('hello');
  });
});

describe('#2 Response.body is a lazy getter over _bodyBuffer', () => {
  test('constructing a Response with a buffered body does not eagerly materialize _body', () => {
    const res = new Response('hello world');
    // Internal — but this is exactly the waste the fix removes: no
    // ReadableStream (and its full byte copy) should exist until `.body` is
    // actually read.
    expect((res as any)._body).toBeNull();
    expect((res as any)._bodyBuffer).not.toBeNull();
  });

  test('accessing .body lazily builds and caches the same stream instance', () => {
    const res = new Response('hello world');
    const first = res.body;
    const second = res.body;
    expect(first).not.toBeNull();
    expect(first).toBe(second);
  });

  test('arrayBuffer()/text() never touch .body and still return the correct bytes', async () => {
    const res = new Response(new Uint8Array([104, 105]));
    expect((res as any)._body).toBeNull();
    expect(await res.text()).toBe('hi');
    // Consuming via text() must not have materialized a stream either — it
    // reads _bodyBuffer directly.
    expect((res as any)._body).toBeNull();
  });

  test('fromNative does not eagerly materialize _body either', () => {
    const res = Response.fromNative({
      status: 200,
      statusText: 'OK',
      headers: [],
      url: 'http://example.test/',
      redirected: false,
      body: new TextEncoder().encode('native body').buffer,
    });
    expect((res as any)._body).toBeNull();
    expect((res as any)._bodyBuffer).not.toBeNull();
  });

  test('accessing .body after the buffered body was already consumed returns an already-used stream', async () => {
    const res = new Response('hello');
    await res.text(); // consumes via _bodyBuffer; _body stays null
    expect((res as any)._body).toBeNull();
    expect(res.bodyUsed).toBe(true);

    // Per spec, a second consumption attempt must reject/throw regardless of
    // whether `.body` was ever touched.
    await expect(res.text()).rejects.toThrow();

    // The lazily-materialized stream must reflect the already-used state —
    // not hand back a fresh, freely-readable stream for a used body.
    const body = res.body;
    expect(body).not.toBeNull();
    expect(body!.locked).toBe(true);
  });
});
