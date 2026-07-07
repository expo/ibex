/**
 * ENG-23114: a JS body-stream failure (or an exhausted awaitWritable pool)
 * must ABORT the host response stream via __exactHttpRespondAbort, never send
 * the clean end-of-stream marker — a clean end makes hyper write a valid
 * chunked terminator over a truncated body that validates as complete on the
 * client.
 */
import { afterEach, expect, test } from "bun:test";
import { serve } from "./index.js";

type AnyFn = (...args: unknown[]) => unknown;
const g = globalThis as Record<string, unknown>;

const STUBBED = [
  "__exactHttpServe",
  "__exactHttpPoll",
  "__exactHttpDrain",
  "__exactHttpWait",
  "__exactHttpRespond",
  "__exactHttpRespondStream",
  "__exactHttpRespondChunkTry",
  "__exactHttpRespondEndTry",
  "__exactHttpRespondAbort",
  "__exactHttpAwaitWritable",
  "__exactHttpClose",
  "__exactHttpSetRef",
];
const saved = new Map<string, unknown>();

function installHostStubs(overrides: Record<string, AnyFn>) {
  const calls: Record<string, unknown[][]> = {};
  const record = (name: string, impl: AnyFn): AnyFn => {
    calls[name] = [];
    return (...args: unknown[]) => {
      calls[name].push(args);
      return impl(...args);
    };
  };

  const pendingRequests: string[] = [];
  const defaults: Record<string, AnyFn> = {
    __exactHttpServe: () => JSON.stringify({ id: 7, port: 8099 }),
    __exactHttpPoll: () => pendingRequests.shift() ?? null,
    __exactHttpDrain: () => null,
    // Park forever: dispatch continues via the sync poll fast-path only.
    __exactHttpWait: () => new Promise(() => {}),
    __exactHttpRespond: () => 0,
    __exactHttpRespondStream: () => 0,
    __exactHttpRespondChunkTry: () => 0,
    __exactHttpRespondEndTry: () => 0,
    __exactHttpRespondAbort: () => 0,
    __exactHttpAwaitWritable: () => Promise.resolve(0),
    __exactHttpClose: () => 0,
    __exactHttpSetRef: () => undefined,
  };

  for (const name of STUBBED) {
    if (!saved.has(name)) saved.set(name, g[name]);
    g[name] = record(name, overrides[name] ?? defaults[name]);
  }

  return {
    calls,
    queueRequest(request: Record<string, unknown>) {
      pendingRequests.push(JSON.stringify(request));
    },
  };
}

afterEach(() => {
  for (const [name, value] of saved) {
    if (value === undefined) delete g[name];
    else g[name] = value;
  }
  saved.clear();
});

function waitFor(predicate: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() > deadline) return reject(new Error("waitFor timed out"));
      setTimeout(tick, 5);
    };
    tick();
  });
}

const TEST_REQUEST = {
  id: 42,
  method: "GET",
  url: "/stream",
  headers: [],
  hasBody: false,
  remoteAddr: "127.0.0.1:55555",
};

test("a mid-stream body error aborts the host stream instead of ending it cleanly", async () => {
  const host = installHostStubs({});
  host.queueRequest(TEST_REQUEST);

  const handle = await serve({
    fetch: () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array([1, 2, 3]));
          },
          pull() {
            const failure = Promise.reject(new Error("boom mid-stream"));
            failure.catch(() => {});
            return failure;
          },
        }),
        { status: 200 },
      ),
  });

  await waitFor(() => host.calls.__exactHttpRespondAbort.length > 0);

  expect(host.calls.__exactHttpRespondStream.length).toBe(1);
  // The first chunk was written before the failure.
  expect(host.calls.__exactHttpRespondChunkTry.length).toBe(1);
  expect(host.calls.__exactHttpRespondAbort).toEqual([[7, 42]]);
  // The clean terminator must NOT be sent for an aborted stream.
  expect(host.calls.__exactHttpRespondEndTry.length).toBe(0);

  await handle.close({ force: true });
});

test("awaitWritable rejection (worker-pool overflow) aborts instead of truncating cleanly", async () => {
  const host = installHostStubs({
    // Channel reports "would block", and the drain wait then rejects the way
    // an exhausted native worker pool does.
    __exactHttpRespondChunkTry: () => 2,
    __exactHttpAwaitWritable: () =>
      Promise.reject(new Error("__exactHttpAwaitWritable queue limit reached")),
  });
  host.queueRequest(TEST_REQUEST);

  const handle = await serve({
    fetch: () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array([9, 9, 9]));
            controller.close();
          },
        }),
        { status: 200 },
      ),
  });

  await waitFor(() => host.calls.__exactHttpRespondAbort.length > 0);

  expect(host.calls.__exactHttpRespondAbort).toEqual([[7, 42]]);
  expect(host.calls.__exactHttpRespondEndTry.length).toBe(0);

  await handle.close({ force: true });
});

test("a completed stream still ends cleanly and never aborts", async () => {
  const host = installHostStubs({});
  host.queueRequest(TEST_REQUEST);

  const handle = await serve({
    fetch: () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array([4, 5, 6]));
            controller.close();
          },
        }),
        { status: 200 },
      ),
  });

  await waitFor(() => host.calls.__exactHttpRespondEndTry.length > 0);

  expect(host.calls.__exactHttpRespondChunkTry.length).toBe(1);
  expect(host.calls.__exactHttpRespondEndTry).toEqual([[7, 42]]);
  expect(host.calls.__exactHttpRespondAbort.length).toBe(0);

  await handle.close({ force: true });
});
