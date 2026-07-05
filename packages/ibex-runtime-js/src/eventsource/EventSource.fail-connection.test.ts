// ENG-22973 — EventSource treated a non-200 status or wrong Content-Type as a
// transient failure: it fired error then reconnected, re-fetching a 404
// endpoint forever with readyState stuck at CONNECTING. Per the SSE spec these
// must fail the connection permanently (readyState CLOSED, one error, no
// reconnect). `response.ok` also wrongly accepted 201-299.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { EventSource } from './EventSource.ts';

const CONNECTING = 0;
const CLOSED = 2;
const flush = () => new Promise((r) => setTimeout(r, 0));

function fakeResponse(status: number, contentType: string) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === 'content-type' ? contentType : null,
    },
    body: null,
  };
}

async function withMockFetch(
  responder: () => any,
  fn: (getCount: () => number) => Promise<void>,
) {
  const realFetch = (globalThis as any).fetch;
  let count = 0;
  (globalThis as any).fetch = () => {
    count++;
    return responder();
  };
  try {
    await fn(() => count);
  } finally {
    (globalThis as any).fetch = realFetch;
  }
}

test('a non-200 status fails the connection permanently', async () => {
  await withMockFetch(
    () => Promise.resolve(fakeResponse(404, 'text/event-stream')),
    async (getCount) => {
      let errorCount = 0;
      const es = new EventSource('http://example.com/sse');
      es.onerror = () => {
        errorCount++;
      };
      await flush();
      expect(es.readyState).toBe(CLOSED);
      expect(errorCount).toBe(1);
      // Give any (buggy) reconnect a chance to fire — it must not.
      await new Promise((r) => setTimeout(r, 30));
      expect(getCount()).toBe(1);
      expect(es.readyState).toBe(CLOSED);
    },
  );
});

test('a 2xx status other than 200 is a failure', async () => {
  await withMockFetch(
    () => Promise.resolve(fakeResponse(201, 'text/event-stream')),
    async () => {
      const es = new EventSource('http://example.com/sse');
      await flush();
      expect(es.readyState).toBe(CLOSED);
    },
  );
});

test('a wrong Content-Type fails the connection permanently', async () => {
  await withMockFetch(
    () => Promise.resolve(fakeResponse(200, 'text/plain')),
    async (getCount) => {
      const es = new EventSource('http://example.com/sse');
      await flush();
      expect(es.readyState).toBe(CLOSED);
      await new Promise((r) => setTimeout(r, 30));
      expect(getCount()).toBe(1);
    },
  );
});

test('a network error stays transient and does not close permanently', async () => {
  await withMockFetch(
    () => Promise.reject(new TypeError('network down')),
    async () => {
      let errorCount = 0;
      const es = new EventSource('http://example.com/sse');
      es.onerror = () => {
        errorCount++;
      };
      await flush();
      // Transient: reconnecting, not permanently closed.
      expect(es.readyState).toBe(CONNECTING);
      expect(errorCount).toBe(1);
      es.close(); // clear the scheduled reconnect timer
      expect(es.readyState).toBe(CLOSED);
    },
  );
});
