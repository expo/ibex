/**
 * ENG-23636: when the host reports hasBody with no pre-buffered bytes, the
 * inbound Request is built with a ReadableStream body. Spec-compliant Request
 * constructors (including the vendored one and Bun's) reject stream bodies
 * unless RequestInit sets duplex: "half" — without it, any bodyless POST
 * (`curl -X POST` with no -d) 400s before routing instead of reaching fetch.
 */
import { afterEach, expect, test } from "bun:test";
import { Request as IbexRequest } from "../fetch/Request.ts";
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

test("a bodyless POST (stream body, no pre-buffered bytes) routes instead of 400ing", async () => {
  // Bun's own Request tolerates a missing duplex; the vendored spec-compliant
  // Request (what Hermes runs) is the one that rejects it. Test against that.
  if (!saved.has("Request")) saved.set("Request", g.Request);
  g.Request = IbexRequest;

  const host = installHostStubs({});
  host.queueRequest({
    id: 42,
    method: "POST",
    url: "/submit",
    headers: [],
    hasBody: true, // host reports a body stream…
    // …but no `body` field: no pre-buffered bytes, so the JS takes the
    // ReadableStream path that previously omitted duplex and threw.
    remoteAddr: "127.0.0.1:55555",
  });

  const seen: Request[] = [];
  const handle = await serve({
    fetch: (request: Request) => {
      seen.push(request);
      return new Response("ok", { status: 200 });
    },
  });

  // Bun's Response("ok") surfaces its body as a stream, so the 200 goes out
  // via RespondStream; the pre-fix constructor 400 goes out via Respond.
  await waitFor(
    () =>
      host.calls.__exactHttpRespond.length > 0 ||
      host.calls.__exactHttpRespondStream.length > 0,
  );

  // The handler must have been reached with the real request…
  expect(seen.length).toBe(1);
  expect(seen[0].method).toBe("POST");
  expect(new URL(seen[0].url).pathname).toBe("/submit");
  // …and no constructor 400 may have been emitted.
  expect(host.calls.__exactHttpRespond.length).toBe(0);
  const [respServerId, respRequestId, respStatus] =
    host.calls.__exactHttpRespondStream[0];
  expect(respServerId).toBe(7);
  expect(respRequestId).toBe(42);
  expect(respStatus).toBe(200);

  await handle.close({ force: true });
});
