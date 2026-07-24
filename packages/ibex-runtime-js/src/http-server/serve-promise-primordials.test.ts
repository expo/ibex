import { afterEach, expect, test } from "bun:test";
import { serve } from "./index.js";

type AnyFn = (...args: unknown[]) => unknown;
type ServeHandle = Awaited<ReturnType<typeof serve>>;

const g = globalThis as Record<string, unknown>;
const NativeError = Error;
const NativePromise = Promise;
const NativeTypeError = TypeError;
const defineProperty = Object.defineProperty;

const HOST_GLOBALS = [
  "__exactHttpServe",
  "__exactHttpPoll",
  "__exactHttpDrain",
  "__exactHttpWait",
  "__exactHttpClose",
  "__exactHttpSetRef",
  "__exactHttpAddress",
] as const;
const savedGlobals = new Map<string, unknown>();
let restoreIntrinsics = () => {};

function install(name: (typeof HOST_GLOBALS)[number], value: AnyFn) {
  if (!savedGlobals.has(name)) {
    savedGlobals.set(name, g[name]);
  }
  g[name] = value;
}

function installHost(serverId: number, wait: AnyFn) {
  const active = new Set<number>();
  const waits: unknown[][] = [];
  const closes: unknown[][] = [];
  const refs: unknown[][] = [];
  let closeResult = 0;

  install("__exactHttpServe", () => {
    active.add(serverId);
    return JSON.stringify({ id: serverId, port: 9000 + serverId });
  });
  install("__exactHttpPoll", () => null);
  install("__exactHttpDrain", () => null);
  install("__exactHttpWait", (...args: unknown[]) => {
    waits.push(args);
    return wait(...args);
  });
  install("__exactHttpClose", (...args: unknown[]) => {
    closes.push(args);
    if (closeResult === 0) {
      active.delete(args[0] as number);
    }
    return closeResult;
  });
  install("__exactHttpSetRef", (...args: unknown[]) => {
    refs.push(args);
  });
  install("__exactHttpAddress", () =>
    JSON.stringify({
      address: "127.0.0.1",
      family: "IPv4",
      port: 9000 + serverId,
    }));

  return {
    active,
    closes,
    refs,
    waits,
    setCloseResult(value: number) {
      closeResult = value;
    },
  };
}

function poisonPromiseIntrinsics(observed: string[]) {
  const targets: Array<[object, PropertyKey, PropertyDescriptor | undefined]> = [
    [Object.prototype, "get", Object.getOwnPropertyDescriptor(Object.prototype, "get")],
    [Object.prototype, "set", Object.getOwnPropertyDescriptor(Object.prototype, "set")],
    [Object.prototype, "error", Object.getOwnPropertyDescriptor(Object.prototype, "error")],
    [Object.prototype, "id", Object.getOwnPropertyDescriptor(Object.prototype, "id")],
    [Object.prototype, "port", Object.getOwnPropertyDescriptor(Object.prototype, "port")],
    [globalThis, "Error", Object.getOwnPropertyDescriptor(globalThis, "Error")],
    [globalThis, "TypeError", Object.getOwnPropertyDescriptor(globalThis, "TypeError")],
    [NativePromise, "resolve", Object.getOwnPropertyDescriptor(NativePromise, "resolve")],
    [NativePromise, Symbol.species, Object.getOwnPropertyDescriptor(NativePromise, Symbol.species)],
    [NativePromise.prototype, "then", Object.getOwnPropertyDescriptor(NativePromise.prototype, "then")],
    [NativePromise.prototype, "catch", Object.getOwnPropertyDescriptor(NativePromise.prototype, "catch")],
    [NativePromise.prototype, "constructor", Object.getOwnPropertyDescriptor(NativePromise.prototype, "constructor")],
    [Object.prototype, "then", Object.getOwnPropertyDescriptor(Object.prototype, "then")],
    [JSON, "parse", Object.getOwnPropertyDescriptor(JSON, "parse")],
    [Reflect, "apply", Object.getOwnPropertyDescriptor(Reflect, "apply")],
    [Object, "defineProperty", Object.getOwnPropertyDescriptor(Object, "defineProperty")],
  ];
  const hostile = (name: string) => {
    observed.push(name);
    throw new NativeError(`hostile ${name}`);
  };

  defineProperty(globalThis, "Error", {
    configurable: true,
    value: function HostileError() {
      return hostile("Error");
    },
    writable: true,
  });
  defineProperty(globalThis, "TypeError", {
    configurable: true,
    value: function HostileTypeError() {
      return hostile("TypeError");
    },
    writable: true,
  });
  defineProperty(NativePromise, "resolve", {
    configurable: true,
    value: () => hostile("Promise.resolve"),
    writable: true,
  });
  defineProperty(NativePromise, Symbol.species, {
    configurable: true,
    get: () => hostile("Promise[Symbol.species]"),
  });
  defineProperty(NativePromise.prototype, "then", {
    configurable: true,
    value: () => hostile("Promise#then"),
    writable: true,
  });
  defineProperty(NativePromise.prototype, "catch", {
    configurable: true,
    value: () => hostile("Promise#catch"),
    writable: true,
  });
  defineProperty(NativePromise.prototype, "constructor", {
    configurable: true,
    get: () => hostile("Promise#constructor"),
  });
  defineProperty(Object.prototype, "then", {
    configurable: true,
    get: () => hostile("Object#then"),
  });
  defineProperty(JSON, "parse", {
    configurable: true,
    value: () => hostile("JSON.parse"),
    writable: true,
  });
  defineProperty(Reflect, "apply", {
    configurable: true,
    value: () => hostile("Reflect.apply"),
    writable: true,
  });
  defineProperty(Object, "defineProperty", {
    configurable: true,
    value: () => hostile("Object.defineProperty"),
    writable: true,
  });
  defineProperty(Object.prototype, "error", {
    configurable: true,
    get: () => hostile("Object#error"),
  });
  defineProperty(Object.prototype, "id", {
    configurable: true,
    get: () => hostile("Object#id"),
  });
  defineProperty(Object.prototype, "port", {
    configurable: true,
    get: () => hostile("Object#port"),
  });
  defineProperty(Object.prototype, "get", {
    configurable: true,
    get: () => hostile("Object#get"),
  });
  defineProperty(Object.prototype, "set", {
    configurable: true,
    get: () => hostile("Object#set"),
  });

  let restored = false;
  restoreIntrinsics = () => {
    if (restored) return;
    restored = true;
    delete (Object.prototype as Record<PropertyKey, unknown>).get;
    delete (Object.prototype as Record<PropertyKey, unknown>).set;
    for (const [target, key, descriptor] of targets) {
      if (descriptor) {
        defineProperty(target, key, descriptor);
      } else {
        delete (target as Record<PropertyKey, unknown>)[key];
      }
    }
    restoreIntrinsics = () => {};
  };
  return restoreIntrinsics;
}

afterEach(() => {
  restoreIntrinsics();
  for (const [name, value] of savedGlobals) {
    if (value === undefined) {
      delete g[name];
    } else {
      g[name] = value;
    }
  }
  savedGlobals.clear();
});

test("serve binds and returns a closeable handle with poisoned Promise intrinsics", async () => {
  const host = installHost(
    91,
    () => new NativePromise(() => {}),
  );
  const observed: string[] = [];
  const restore = poisonPromiseIntrinsics(observed);

  let handlePromise: ReturnType<typeof serve> | undefined;
  try {
    handlePromise = serve({
      fetch: () => new Response("ok"),
      hostname: "127.0.0.1",
      port: 0,
    });
  } finally {
    restore();
  }

  const handle = await handlePromise as ServeHandle;
  expect(host.active).toEqual(new Set([91]));
  expect(host.waits).toHaveLength(4);

  install("__exactHttpAddress", () => {
    observed.push("mutable __exactHttpAddress");
    throw new NativeError("mutable __exactHttpAddress");
  });
  install("__exactHttpClose", () => {
    observed.push("mutable __exactHttpClose");
    return -1;
  });
  install("__exactHttpSetRef", () => {
    observed.push("mutable __exactHttpSetRef");
    return -1;
  });

  const restoreAddressIntrinsics = poisonPromiseIntrinsics(observed);
  let address: ReturnType<ServeHandle["address"]>;
  try {
    address = handle.address();
  } finally {
    restoreAddressIntrinsics();
  }
  expect(observed).toEqual([]);
  expect(address).toEqual({
    address: "127.0.0.1",
    family: "IPv4",
    port: 9091,
  });

  handle.ref();
  handle.unref();
  expect(host.refs).toEqual([[91, 1], [91, 0]]);

  await handle.close({ force: true });
  expect(host.closes).toEqual([[91, 1]]);
  expect(host.active.size).toBe(0);
});

test("hostile response capability getters fail before the native bind", () => {
  const host = installHost(
    94,
    () => new NativePromise(() => {}),
  );
  const responseTextDescriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "__exactHttpRespondText",
  );
  try {
    defineProperty(globalThis, "__exactHttpRespondText", {
      configurable: true,
      get() {
        throw new NativeError("respond getter poison");
      },
    });
    expect(() =>
      serve({
        fetch: () => new Response("ok"),
        hostname: "127.0.0.1",
        port: 0,
      })).toThrow("respond getter poison");
  } finally {
    if (responseTextDescriptor) {
      defineProperty(
        globalThis,
        "__exactHttpRespondText",
        responseTextDescriptor,
      );
    } else {
      delete g.__exactHttpRespondText;
    }
  }

  expect(host.active.size).toBe(0);
  expect(host.waits).toHaveLength(0);
  expect(host.closes).toHaveLength(0);
});

test("invalid hostname coercion fails before the native bind", () => {
  const host = installHost(
    95,
    () => new NativePromise(() => {}),
  );
  let coercionCalls = 0;
  const hostileHostname = {
    [Symbol.toPrimitive]() {
      coercionCalls += 1;
      throw new NativeError("hostname coercion poison");
    },
  };

  expect(() =>
    serve({
      fetch: () => new Response("ok"),
      hostname: hostileHostname as unknown as string,
      port: 0,
    })).toThrow("serve() hostname must be a string");

  expect(coercionCalls).toBe(0);
  expect(host.active.size).toBe(0);
  expect(host.waits).toHaveLength(0);
  expect(host.closes).toHaveLength(0);
});

test("serve force-closes the exact listener when post-bind waiter setup fails", () => {
  const host = installHost(92, () => ({}));

  expect(() =>
    serve({
      fetch: () => new Response("ok"),
    })).toThrow();

  expect(host.waits).toEqual([[92, 1000]]);
  expect(host.closes).toEqual([[92, 1]]);
  expect(host.active.size).toBe(0);
});

test("failed construction cleanup exposes a retryable exact listener handle", async () => {
  const host = installHost(93, () => ({}));
  host.setCloseResult(-1);
  const observed: string[] = [];
  const restore = poisonPromiseIntrinsics(observed);

  let failure: unknown;
  try {
    try {
      serve({
        fetch: () => new Response("ok"),
        hostname: "127.0.0.1",
        port: 0,
      });
    } catch (error) {
      failure = error;
    }
  } finally {
    restore();
  }

  const recoveryHandle = (
    failure as Error & { recoveryHandle: ServeHandle }
  ).recoveryHandle;
  const recoveryDescriptor = Object.getOwnPropertyDescriptor(
    failure as object,
    "recoveryHandle",
  );
  expect(observed).toEqual([]);
  expect(failure).toBeInstanceOf(Error);
  expect(recoveryHandle).toBeDefined();
  expect(recoveryDescriptor).toEqual({
    configurable: false,
    enumerable: false,
    value: recoveryHandle,
    writable: false,
  });
  expect(host.closes).toEqual([[93, 1]]);
  expect(host.active).toEqual(new Set([93]));

  expect(() => recoveryHandle.close({ force: true }))
    .toThrow("Exact HTTP server close failed");
  expect(host.closes).toEqual([[93, 1], [93, 1]]);
  expect(host.active).toEqual(new Set([93]));

  host.setCloseResult(0);
  await recoveryHandle.close({ force: true });
  expect(host.closes).toEqual([[93, 1], [93, 1], [93, 1]]);
  expect(host.active.size).toBe(0);
});
