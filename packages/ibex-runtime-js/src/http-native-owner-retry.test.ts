import { afterAll, afterEach, expect, test } from "bun:test";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const g = globalThis as Record<string, unknown>;
const originalHttpOwner = g.__exactHttpOwner;
const originalNetOwner = g.__exactNetOwner;
let httpOwnerImpl: ((serverId: number) => unknown) | undefined;
type NetOwnerImpl = (action: string, stamp?: number, handle?: number) => unknown;
const permissiveNetOwner: NetOwnerImpl = (action) =>
  action === "new" ? 1 : undefined;
let netOwnerImpl: NetOwnerImpl = permissiveNetOwner;
const httpOwnerDispatcher = (serverId: number) => {
  if (!httpOwnerImpl) throw new Error("HTTP response owner check is unavailable");
  return httpOwnerImpl(serverId);
};
const netOwnerDispatcher: NetOwnerImpl = (action, stamp, handle) =>
  netOwnerImpl(action, stamp, handle);
// http.js intentionally captures this host identity during module evaluation.
g.__exactHttpOwner = httpOwnerDispatcher;
g.__exactNetOwner = netOwnerDispatcher;
const http = require("../../../src/builtins/http.js");
const net = require("node:net");
const EventEmitter = require("node:events").EventEmitter;

const EVENT_METHODS = [
  "emit",
  "on",
  "addListener",
  "once",
  "prependListener",
  "prependOnceListener",
  "removeListener",
  "off",
  "removeAllListeners",
  "listeners",
  "rawListeners",
  "listenerCount",
  "eventNames",
  "getMaxListeners",
  "setMaxListeners",
] as const;

const HOST_GLOBALS = [
  "__exactHttpAddress",
  "__exactHttpOwner",
  "__exactHttpRespond",
  "__exactHttpRespondString",
  "__exactHttpRespondStream",
  "__exactHttpRespondChunkTry",
  "__exactHttpRespondEndTry",
  "__exactHttpRespondAbort",
  "__exactHttpRespondEnd",
  "__exactHttpAwaitWritable",
  "__exactHttpServe",
  "__exactHttpPoll",
  "__exactHttpWait",
  "__exactHttpClose",
] as const;

const savedGlobals = new Map<string, unknown>();
const originalCreateServer = net.createServer;

function install(name: (typeof HOST_GLOBALS)[number], value?: unknown) {
  if (name === "__exactHttpOwner") {
    httpOwnerImpl = value as ((serverId: number) => unknown) | undefined;
    return;
  }
  if (!savedGlobals.has(name)) savedGlobals.set(name, g[name]);
  if (value === undefined) delete g[name];
  else g[name] = value;
}

function ownerError(operation: string): Error {
  return new Error(`${operation}: server belongs to a different principal`);
}

function nextTurn(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 10));
}

afterEach(() => {
  net.createServer = originalCreateServer;
  httpOwnerImpl = undefined;
  netOwnerImpl = permissiveNetOwner;
  g.__exactHttpOwner = httpOwnerDispatcher;
  g.__exactNetOwner = netOwnerDispatcher;
  for (const [name, value] of savedGlobals) {
    if (value === undefined) delete g[name];
    else g[name] = value;
  }
  savedGlobals.clear();
});

afterAll(() => {
  if (originalHttpOwner === undefined) delete g.__exactHttpOwner;
  else g.__exactHttpOwner = originalHttpOwner;
  if (originalNetOwner === undefined) delete g.__exactNetOwner;
  else g.__exactNetOwner = originalNetOwner;
});

test("foreign ServerResponse.end cannot poison state, body, callback, or selectors before owner retry", async () => {
  let principal = "owner";
  const responses: unknown[][] = [];
  let foreignFinishCalls = 0;

  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpAddress", (serverId: number) => {
    if (principal !== "owner") throw ownerError("__exactHttpAddress");
    return JSON.stringify({ address: "127.0.0.1", family: "IPv4", port: serverId });
  });
  install("__exactHttpRespond", (...args: unknown[]) => {
    if (principal !== "owner") throw ownerError("__exactHttpRespond");
    responses.push(args);
    return 0;
  });
  install("__exactHttpRespondString");
  install("__exactHttpRespondStream");

  // Replacing the public global cannot replace http.js's captured owner check.
  g.__exactHttpOwner = () => true;

  const response = new http.ServerResponse(7, 42);
  principal = "foreign";
  expect(() => response._serverId).toThrow("native selector is private");
  expect(() => { response._serverId = 999; }).toThrow("native selector is private");
  expect(() => response._requestId).toThrow("native selector is private");
  expect(() => { response._requestId = 999; }).toThrow("native selector is private");
  expect(() => response._nativeMode).toThrow("native selector is private");
  expect(() => { response._nativeMode = false; }).toThrow("native selector is private");

  expect(() => response.end("foreign-body", () => { foreignFinishCalls++; }))
    .toThrow("different principal");
  expect(response.finished).toBe(false);
  expect(response.writableEnded).toBe(false);
  expect(response.destroyed).toBe(false);

  principal = "owner";
  expect(response._bodyParts).toEqual([]);
  let ownerFinishCalls = 0;
  response.end("owner-body", () => { ownerFinishCalls++; });
  await nextTurn();

  expect(responses).toHaveLength(1);
  expect(responses[0][0]).toBe(7);
  expect(responses[0][1]).toBe(42);
  expect(Buffer.from(responses[0][4] as Uint8Array).toString()).toBe("owner-body");
  expect(response.finished).toBe(true);
  expect(response.writableEnded).toBe(true);
  expect(ownerFinishCalls).toBe(1);
  expect(foreignFinishCalls).toBe(0);
});

test("foreign ServerResponse.destroy leaves abort and terminal state retryable by the owner", () => {
  let principal = "owner";
  const aborts: unknown[][] = [];
  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpRespondAbort", (...args: unknown[]) => {
    if (principal !== "owner") throw ownerError("__exactHttpRespondAbort");
    aborts.push(args);
    return 0;
  });

  const response = new http.ServerResponse(8, 43);
  principal = "foreign";
  const foreignError = new Error("foreign destroy");
  expect(() => response.destroy(foreignError)).toThrow("different principal");
  expect(response.finished).toBe(false);
  expect(response.destroyed).toBe(false);
  expect(response.closed).toBe(false);
  principal = "owner";
  expect(response.errored).toBeUndefined();

  const ownerErrorValue = new Error("owner destroy");
  response.destroy(ownerErrorValue);
  expect(aborts).toEqual([[8, 43]]);
  expect(response.finished).toBe(true);
  expect(response.destroyed).toBe(true);
  expect(response.closed).toBe(true);
  expect(response.errored).toBe(ownerErrorValue);
});

test("foreign ServerResponse EventEmitter access cannot inspect, subscribe to, or poison owner events", async () => {
  let principal = "owner";
  let ownerCalls = 0;
  let foreignCalls = 0;
  let finishCalls = 0;
  const ownerListener = () => {
    ownerCalls++;
  };
  const foreignListener = () => {
    foreignCalls++;
  };

  netOwnerImpl = (action, stamp) => {
    if (action === "new") return 302;
    if (action !== "assert" || stamp !== 302) {
      throw new Error("__exactNetOwner: invalid owner stamp operation");
    }
    if (principal !== "owner") throw ownerError("__exactNetOwner");
    return undefined;
  };

  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpRespond", () => 0);

  const response = new http.ServerResponse(81, 43);
  response.on("owner-event", ownerListener);
  response.once("finish", () => {
    finishCalls++;
  });
  for (const method of EVENT_METHODS) {
    const descriptor = Object.getOwnPropertyDescriptor(response, method);
    expect(descriptor?.configurable).toBe(false);
  }

  principal = "foreign";
  expect(() => response.on("owner-event", foreignListener)).toThrow("different principal");
  expect(() => response.addListener("owner-event", foreignListener)).toThrow("different principal");
  expect(() => response.removeListener("owner-event", ownerListener)).toThrow("different principal");
  expect(() => response.removeAllListeners("owner-event")).toThrow("different principal");
  expect(() => response.listeners("owner-event")).toThrow("different principal");
  expect(() => response._events).toThrow("different principal");
  expect(() => {
    response._events = Object.create(null);
  }).toThrow("different principal");
  expect(() => {
    response.emit = foreignListener;
  }).toThrow("different principal");
  expect(() => EventEmitter.prototype.on.call(response, "owner-event", foreignListener))
    .toThrow("different principal");
  expect(() => EventEmitter.prototype.removeAllListeners.call(response, "owner-event"))
    .toThrow("different principal");
  expect(() => EventEmitter.prototype.emit.call(response, "owner-event"))
    .toThrow("different principal");

  principal = "owner";
  expect(response.listeners("owner-event")).toEqual([ownerListener]);
  response.emit("owner-event");
  expect(ownerCalls).toBe(1);
  expect(foreignCalls).toBe(0);

  // Native release precedes deferred finish/close. The construction identity
  // must keep that interval owner-only even though the HTTP selectors are gone.
  response.end("owner-body");
  principal = "foreign";
  expect(() => response.removeAllListeners("finish")).toThrow("different principal");
  expect(() => EventEmitter.prototype.on.call(response, "finish", foreignListener))
    .toThrow("different principal");
  principal = "owner";
  await nextTurn();
  expect(finishCalls).toBe(1);
  expect(foreignCalls).toBe(0);
});

test("foreign ServerResponse field, nested collection, callback, and method mutations are isolated", async () => {
  let principal = "owner";
  let drainCalls = 0;
  let errorCalls = 0;
  let foreignCalls = 0;
  const responses: unknown[][] = [];
  const ownerReq = { method: "GET", owner: true };
  const ownerDrain = () => { drainCalls++; };
  const ownerSocketError = () => { errorCalls++; };
  const foreignCallback = () => { foreignCalls++; };

  netOwnerImpl = (action, stamp) => {
    if (action === "new") return 304;
    if (action !== "assert" || stamp !== 304) throw new Error("invalid owner stamp");
    if (principal !== "owner") throw ownerError("__exactNetOwner");
    return undefined;
  };
  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpRespond", (...args: unknown[]) => {
    responses.push(args);
    return 0;
  });

  const response = new http.ServerResponse(83, 44);
  response._req = ownerReq;
  response.req = ownerReq;
  response._rejectNonStandardBodyWrites = false;
  response._uniqueHeaders = Object.create(null);
  response._uniqueHeaders["x-owner"] = true;
  response._outgoingHighWaterMark = 8192;
  response._useChunkedEncoding = false;
  response._socketDrainListener = ownerDrain;
  response._socketErrorListener = ownerSocketError;

  principal = "foreign";
  for (const mutate of [
    () => { response._req = { foreign: true }; },
    () => { response.req = { foreign: true }; },
    () => { response._rejectNonStandardBodyWrites = true; },
    () => { response._uniqueHeaders = { foreign: true }; },
    () => { response._outgoingHighWaterMark = 1; },
    () => { response._useChunkedEncoding = true; },
    () => { response._socketDrainListener = foreignCallback; },
    () => { response._socketErrorListener = foreignCallback; },
    () => { response.errored = new Error("foreign"); },
    () => { response.end = foreignCallback; },
  ]) {
    expect(mutate).toThrow("different principal");
  }
  expect(() => { response._uniqueHeaders["x-foreign"] = true; })
    .toThrow("different principal");
  expect(() => response._bodyParts.push("foreign-body"))
    .toThrow("different principal");
  expect(() => response.socket).toThrow("different principal");
  expect(() => Object.defineProperty(response, "writeHead", { value: foreignCallback }))
    .toThrow();

  principal = "owner";
  expect(response._req).toBe(ownerReq);
  expect(response.req).toBe(ownerReq);
  expect(response._rejectNonStandardBodyWrites).toBe(false);
  expect(response._uniqueHeaders).toEqual({ "x-owner": true });
  expect(response._outgoingHighWaterMark).toBe(8192);
  expect(response._useChunkedEncoding).toBe(false);
  expect(response._socketDrainListener).toBe(ownerDrain);
  expect(response._socketErrorListener).toBe(ownerSocketError);
  response._socketDrainListener();
  response._socketErrorListener();
  response.setHeader("x-owner", "yes");
  response.end("owner-body");
  await nextTurn();

  expect(drainCalls).toBe(1);
  expect(errorCalls).toBe(1);
  expect(foreignCalls).toBe(0);
  expect(responses).toHaveLength(1);
  expect(Buffer.from(responses[0][4] as Uint8Array).toString()).toBe("owner-body");
});

test("foreign writes cannot append work behind an owner-scheduled native backpressure wait", async () => {
  let principal = "owner";
  let writableResolve: ((value: number) => void) | undefined;
  let channelWritable = false;
  const chunks: string[] = [];

  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpAddress", () => {
    if (principal !== "owner") throw ownerError("__exactHttpAddress");
    return "{}";
  });
  install("__exactHttpRespondStream", () => {
    if (principal !== "owner") throw ownerError("__exactHttpRespondStream");
    return 0;
  });
  install("__exactHttpRespondChunkTry", (_serverId: number, _requestId: number, body: Uint8Array) => {
    if (principal !== "owner") throw ownerError("__exactHttpRespondChunkTry");
    if (!channelWritable) return 2;
    chunks.push(Buffer.from(body).toString());
    return 0;
  });
  install("__exactHttpRespondEndTry", () => {
    if (principal !== "owner") throw ownerError("__exactHttpRespondEndTry");
    return 0;
  });
  install("__exactHttpAwaitWritable", () => new Promise<number>((resolve) => {
    writableResolve = resolve;
  }));

  const response = new http.ServerResponse(9, 44);
  expect(response.write("owner-chunk")).toBe(false);
  expect(response._nativeWriteInFlight).toBe(true);

  principal = "foreign";
  expect(() => response.write("foreign-chunk")).toThrow("different principal");

  principal = "owner";
  expect(response._nativeWriteQueue).toHaveLength(1);
  channelWritable = true;
  writableResolve?.(0);
  await nextTurn();
  response.end();
  await nextTurn();

  expect(chunks).toEqual(["owner-chunk"]);
  expect(response.finished).toBe(true);
});

test("owner can finish a native response after positive HTTP authority is revoked", async () => {
  let principal = "owner";
  let revoked = false;
  let addressCalls = 0;
  let endCalls = 0;
  const chunks: string[] = [];

  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpAddress", () => {
    addressCalls++;
    if (revoked) throw new Error("Permission denied: __exactHttpAddress");
    return "{}";
  });
  install("__exactHttpRespondStream", () => {
    if (revoked) throw new Error("Permission denied: __exactHttpRespondStream");
    return 0;
  });
  install("__exactHttpRespondChunkTry", (_serverId: number, _requestId: number, body: Uint8Array) => {
    if (revoked) throw new Error("Permission denied: __exactHttpRespondChunkTry");
    chunks.push(Buffer.from(body).toString());
    return 0;
  });
  install("__exactHttpRespondEndTry", () => {
    if (principal !== "owner") throw ownerError("__exactHttpRespondEndTry");
    endCalls++;
    return 0;
  });
  install("__exactHttpAwaitWritable", () => Promise.resolve(0));

  const response = new http.ServerResponse(10, 45);
  expect(response.write("authorized-before-revoke")).toBe(true);
  revoked = true;
  response.end();
  await nextTurn();

  expect(chunks).toEqual(["authorized-before-revoke"]);
  expect(endCalls).toBe(1);
  expect(addressCalls).toBe(0);
  expect(response.finished).toBe(true);
  expect(response.writableEnded).toBe(true);
});

test("foreign socket-backed response mutations fail before poisoning owner output", async () => {
  let principal = "owner";
  const writes: string[] = [];
  const socket: Record<string | symbol, any> = {
    destroyed: false,
    writableNeedDrain: false,
    writableHighWaterMark: 16_384,
    _pendingServiceUnavailableCount: 0,
    parser: {},
    on() {},
    removeListener() {},
    write(chunk: unknown, callback?: (err?: Error) => void) {
      if (principal !== "owner") throw ownerError("socket.write");
      writes.push(Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk));
      callback?.();
      return true;
    },
    end(chunk?: unknown, callback?: () => void) {
      if (principal !== "owner") throw ownerError("socket.end");
      if (chunk != null) writes.push(Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk));
      callback?.();
      return this;
    },
    destroy() {
      if (principal !== "owner") throw ownerError("socket.destroy");
      this.destroyed = true;
      return this;
    },
  };
  Object.defineProperty(socket, "_handle", {
    configurable: false,
    get() {
      if (principal !== "owner") throw ownerError("socket owner check");
      return { fd: 17 };
    },
  });

  const response = new http.ServerResponse({
    method: "GET",
    headers: { connection: "close" },
    httpVersionMajor: 1,
    httpVersionMinor: 1,
    complete: true,
  });
  response.assignSocket(socket);

  principal = "foreign";
  const attackerSocket = {
    write() { writes.push("attacker-socket"); return true; },
    end() { writes.push("attacker-socket-end"); },
  };
  expect(() => { response.socket = attackerSocket; })
    .toThrow("different principal");
  expect(() => { response.connection = attackerSocket; })
    .toThrow("different principal");
  expect(() => response.socket).toThrow("different principal");
  principal = "owner";
  expect(response.socket).toBe(socket);
  principal = "foreign";
  expect(() => response.setHeader("x-foreign", "poison"))
    .toThrow("different principal");
  expect(() => response.appendHeader("x-foreign", "poison"))
    .toThrow("different principal");
  expect(() => response.write("foreign-body"))
    .toThrow("different principal");
  expect(() => response.end("foreign-final"))
    .toThrow("different principal");
  expect(() => http.OutgoingMessage.prototype.write.call(response, "base-write"))
    .toThrow("different principal");
  expect(() => http.OutgoingMessage.prototype.end.call(response, "base-end"))
    .toThrow("different principal");
  expect(() => http.OutgoingMessage.prototype.destroy.call(response))
    .toThrow("different principal");
  expect(() => response._bodyParts.push(Buffer.from("direct-body")))
    .toThrow("different principal");
  expect(() => { response._headers["x-direct"] = "poison"; })
    .toThrow("different principal");
  expect(() => { response._finished = true; })
    .toThrow("different principal");
  expect(() => { response.destroyed = true; })
    .toThrow("different principal");
  expect(response.finished).toBe(false);
  expect(response.writableEnded).toBe(false);
  expect(writes).toEqual([]);

  principal = "owner";
  expect(response._bodyParts).toEqual([]);
  expect(response.getHeader("x-foreign")).toBeUndefined();
  response.setHeader("x-owner", "ok");
  response.end("owner-body");
  await nextTurn();

  expect(writes.join("")).toContain("x-owner: ok");
  expect(writes.join("")).not.toContain("x-foreign");
  expect(writes.join("")).toContain("owner-body");
  expect(writes.join("")).not.toContain("foreign");
  expect(writes.join("")).not.toContain("base-");
  expect(writes.join("")).not.toContain("attacker-socket");
  expect(response.finished).toBe(true);
});

test("http.Server.close authenticates and succeeds before committing closing state or selector loss", async () => {
  let principal = "owner";
  let failOwnerClose = false;
  const closes: unknown[][] = [];
  let foreignCloseCalls = 0;
  let failedCloseCalls = 0;
  let serveCalls = 0;

  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpServe", () => {
    serveCalls++;
    return JSON.stringify({ id: 31, port: 8131 });
  });
  install("__exactHttpPoll", () => null);
  install("__exactHttpWait", () => new Promise(() => {}));
  install("__exactHttpClose", (...args: unknown[]) => {
    if (principal !== "owner") throw ownerError("__exactHttpClose");
    if (failOwnerClose) return -1;
    closes.push(args);
    return 0;
  });

  net.createServer = undefined;
  const server = new http.Server();
  net.createServer = originalCreateServer;
  server.listen(0, "127.0.0.1");
  await nextTurn();

  expect(server.listening).toBe(true);
  expect(server._closing).toBe(false);
  expect(() => server._serverId).toThrow("native selector is private");
  expect(() => { server._serverId = 999; }).toThrow("native selector is private");

  principal = "foreign";
  expect(() => { server._useNative = false; }).toThrow("different principal");
  expect(() => { server._closing = true; }).toThrow("different principal");
  expect(() => { server._listening = false; }).toThrow("different principal");
  expect(() => server.listen(9999)).toThrow("different principal");
  expect(serveCalls).toBe(1);
  expect(() => server.close(() => { foreignCloseCalls++; })).toThrow("different principal");
  principal = "owner";
  expect(server.listening).toBe(true);
  expect(server._closing).toBe(false);

  failOwnerClose = true;
  expect(() => server.close(() => { failedCloseCalls++; })).toThrow("HTTP server close failed");
  expect(server.listening).toBe(true);
  expect(server._closing).toBe(false);

  failOwnerClose = false;
  let ownerCloseCalls = 0;
  server.close(() => { ownerCloseCalls++; });
  await nextTurn();

  expect(closes).toEqual([[31, 0]]);
  expect(server.listening).toBe(false);
  expect(server._closing).toBe(true);
  expect(ownerCloseCalls).toBe(1);
  expect(foreignCloseCalls).toBe(0);
  expect(failedCloseCalls).toBe(0);
});

test("foreign http.Server field, nested Set, config callback, and method mutations are isolated", async () => {
  let principal = "owner";
  let foreignCalls = 0;
  let ownerUpgradeCalls = 0;
  const foreignCallback = () => { foreignCalls++; };
  const ownerUpgrade = () => { ownerUpgradeCalls++; return true; };

  netOwnerImpl = (action, stamp) => {
    if (action === "new") return 305;
    if (action !== "assert" || stamp !== 305) throw new Error("invalid owner stamp");
    if (principal !== "owner") throw ownerError("__exactNetOwner");
    return undefined;
  };
  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpServe", () => JSON.stringify({ id: 84, port: 8184 }));
  install("__exactHttpPoll", () => null);
  install("__exactHttpWait", () => new Promise(() => {}));
  install("__exactHttpClose", () => 0);

  net.createServer = undefined;
  const server = new http.Server({
    shouldUpgradeCallback: ownerUpgrade,
    uniqueHeaders: ["x-owner"],
    requestTimeout: 3210,
  });
  net.createServer = originalCreateServer;

  principal = "foreign";
  for (const mutate of [
    () => { server._sockets = new Set(); },
    () => { server._netServer = { foreign: true }; },
    () => { server.shouldUpgradeCallback = foreignCallback; },
    () => { server._incomingMessageCtor = foreignCallback; },
    () => { server._serverResponseCtor = foreignCallback; },
    () => { server.requestTimeout = 1; },
    () => { server._socketTimeoutApplier = foreignCallback; },
    () => { server.listen = foreignCallback; },
  ]) {
    expect(mutate).toThrow("different principal");
  }
  expect(() => server._sockets.add({ foreign: true })).toThrow("different principal");
  expect(() => { server._uniqueHeaders["x-foreign"] = true; })
    .toThrow("different principal");
  expect(() => Object.defineProperty(server, "close", { value: foreignCallback }))
    .toThrow();

  principal = "owner";
  expect(server._sockets.size).toBe(0);
  expect(server._netServer).toBeNull();
  expect(server.shouldUpgradeCallback).toBe(ownerUpgrade);
  expect(server.requestTimeout).toBe(3210);
  expect(server._uniqueHeaders).toEqual({ "x-owner": true });
  expect(typeof server.listen).toBe("function");
  expect(typeof server.close).toBe("function");
  expect(server.shouldUpgradeCallback({})).toBe(true);
  server.listen(0, "127.0.0.1");
  await nextTurn();
  let closeCalls = 0;
  server.close(() => { closeCalls++; });
  await nextTurn();

  expect(ownerUpgradeCalls).toBe(1);
  expect(foreignCalls).toBe(0);
  expect(closeCalls).toBe(1);
});

test("foreign native http.Server EventEmitter access cannot poison owner dispatch or cleanup", async () => {
  let principal = "owner";
  let ownerCalls = 0;
  let foreignCalls = 0;
  let closeCalls = 0;
  const ownerListener = () => {
    ownerCalls++;
  };
  const foreignListener = () => {
    foreignCalls++;
  };

  netOwnerImpl = (action, stamp) => {
    if (action === "new") return 303;
    if (action !== "assert" || stamp !== 303) {
      throw new Error("__exactNetOwner: invalid owner stamp operation");
    }
    if (principal !== "owner") throw ownerError("__exactNetOwner");
    return undefined;
  };

  install("__exactHttpOwner", () => {
    if (principal !== "owner") throw ownerError("__exactHttpOwner");
    return true;
  });
  install("__exactHttpServe", () => JSON.stringify({ id: 82, port: 8182 }));
  install("__exactHttpPoll", () => null);
  install("__exactHttpWait", () => new Promise(() => {}));
  install("__exactHttpClose", () => {
    if (principal !== "owner") throw ownerError("__exactHttpClose");
    return 0;
  });

  net.createServer = undefined;
  const server = new http.Server();
  net.createServer = originalCreateServer;
  server.on("owner-event", ownerListener);
  server.once("close", () => {
    closeCalls++;
  });

  // The construction-time network stamp closes the otherwise-unowned window
  // before native listen returns an HTTP server id.
  principal = "foreign";
  expect(() => server.on("owner-event", foreignListener)).toThrow("different principal");
  expect(() => EventEmitter.prototype.on.call(server, "owner-event", foreignListener))
    .toThrow("different principal");
  expect(() => {
    server._events = Object.create(null);
  }).toThrow("different principal");

  principal = "owner";
  server.listen(0, "127.0.0.1");
  await nextTurn();

  for (const method of EVENT_METHODS) {
    const descriptor = Object.getOwnPropertyDescriptor(server, method);
    expect(descriptor?.configurable).toBe(false);
  }
  principal = "foreign";
  expect(() => server.on("owner-event", foreignListener)).toThrow("different principal");
  expect(() => server.addListener("owner-event", foreignListener)).toThrow("different principal");
  expect(() => server.removeListener("owner-event", ownerListener)).toThrow("different principal");
  expect(() => server.removeAllListeners("owner-event")).toThrow("different principal");
  expect(() => server.listeners("owner-event")).toThrow("different principal");
  expect(() => server._events).toThrow("different principal");
  expect(() => {
    server._events = Object.create(null);
  }).toThrow("different principal");
  expect(() => {
    server.emit = foreignListener;
  }).toThrow("different principal");
  expect(() => EventEmitter.prototype.on.call(server, "owner-event", foreignListener))
    .toThrow("different principal");
  expect(() => EventEmitter.prototype.removeAllListeners.call(server, "owner-event"))
    .toThrow("different principal");
  expect(() => EventEmitter.prototype.emit.call(server, "owner-event"))
    .toThrow("different principal");

  principal = "owner";
  expect(server.listeners("owner-event")).toEqual([ownerListener]);
  server.emit("owner-event");
  expect(ownerCalls).toBe(1);
  expect(foreignCalls).toBe(0);

  server.close();
  await nextTurn();
  expect(closeCalls).toBe(1);
});

test("a stale native wait cannot inject an old request into a relistened server generation", async () => {
  const servedIds = [41, 42];
  const waitResolvers = new Map<number, Array<(json: string) => void>>();
  const closes: unknown[][] = [];
  const aborts: unknown[][] = [];
  const seenUrls: string[] = [];

  install("__exactHttpOwner", () => true);
  install("__exactHttpServe", () => {
    const id = servedIds.shift();
    return JSON.stringify({ id, port: 8100 + Number(id) });
  });
  install("__exactHttpPoll", () => null);
  install("__exactHttpWait", (serverId: number) => new Promise<string>((resolve) => {
    const resolvers = waitResolvers.get(serverId) ?? [];
    resolvers.push(resolve);
    waitResolvers.set(serverId, resolvers);
  }));
  install("__exactHttpClose", (...args: unknown[]) => {
    closes.push(args);
    return 0;
  });
  install("__exactHttpRespondAbort", (...args: unknown[]) => {
    aborts.push(args);
    return 0;
  });

  net.createServer = undefined;
  const server = new http.Server((req: { url: string }, res: { destroy(): void }) => {
    seenUrls.push(req.url);
    res.destroy();
  });
  net.createServer = originalCreateServer;

  server.listen(0, "127.0.0.1");
  await nextTurn();
  expect(waitResolvers.get(41)).toHaveLength(1);

  server.close();
  await nextTurn();
  server.listen(0, "127.0.0.1");
  await nextTurn();
  expect(waitResolvers.get(42)).toHaveLength(1);

  const staleRequest = JSON.stringify({
    id: 101,
    method: "GET",
    url: "/stale",
    headers: [],
    hasBody: false,
  });
  waitResolvers.get(41)?.[0](staleRequest);
  await nextTurn();
  expect(seenUrls).toEqual([]);
  expect(aborts).toEqual([]);

  const currentRequest = JSON.stringify({
    id: 202,
    method: "GET",
    url: "/current",
    headers: [],
    hasBody: false,
  });
  waitResolvers.get(42)?.[0](currentRequest);
  await nextTurn();
  expect(seenUrls).toEqual(["/current"]);
  expect(aborts).toEqual([[42, 202]]);

  server.close();
  await nextTurn();
  expect(closes).toEqual([[41, 0], [42, 0]]);
});
