import { serve } from "./index.js";

const g = globalThis as typeof globalThis & Record<string, unknown>;
const defineProperty = Object.defineProperty;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const intrinsicError = Error;
const intrinsicPromise = Promise;
const stringify = JSON.stringify;

let promiseConstructorReads = 0;
let promiseResolveCalls = 0;
let promiseSpeciesReads = 0;
let promiseThenCalls = 0;
let nextServerId = 40;
const waitPromises: Promise<unknown>[] = [];

defineProperty(intrinsicPromise.prototype, "constructor", {
  configurable: true,
  get() {
    promiseConstructorReads += 1;
    throw new intrinsicError("poisoned Promise.prototype.constructor");
  },
});
defineProperty(intrinsicPromise.prototype, "then", {
  configurable: true,
  value() {
    promiseThenCalls += 1;
    throw new intrinsicError("poisoned Promise.prototype.then");
  },
  writable: true,
});
defineProperty(intrinsicPromise, Symbol.species, {
  configurable: true,
  get() {
    promiseSpeciesReads += 1;
    throw new intrinsicError("poisoned Promise[Symbol.species]");
  },
});
defineProperty(intrinsicPromise, "resolve", {
  configurable: true,
  value() {
    promiseResolveCalls += 1;
    throw new intrinsicError("poisoned Promise.resolve");
  },
  writable: true,
});

g.__exactHttpServe = () =>
  stringify({ id: ++nextServerId, port: 49_332 });
g.__exactHttpPoll = () => null;
g.__exactHttpDrain = () => null;
g.__exactHttpWait = () => {
  const promise = new intrinsicPromise<unknown>(() => {});
  waitPromises.push(promise);
  return promise;
};
g.__exactHttpClose = () => 0;
g.__exactHttpSetRef = () => {};
g.__exactHttpAddress = () =>
  stringify({
    address: "127.0.0.1",
    family: "IPv4",
    port: 49_332,
  });

const handlePromise = serve({
  fetch: () => {
    throw new intrinsicError("fixture fetch should not run");
  },
  hostname: "127.0.0.1",
  port: 49_332,
});
const selectedCapturedPromise =
  waitPromises.length === 4 &&
  waitPromises.every(
    (promise) =>
      getOwnPropertyDescriptor(promise, "constructor")?.value ===
      intrinsicPromise,
  );

(g.print as (value: string) => void)(
  stringify({
    handlePromise: handlePromise instanceof intrinsicPromise,
    ok: true,
    promiseConstructorReads,
    promiseResolveCalls,
    promiseSpeciesReads,
    promiseThenCalls,
    selectedCapturedPromise,
    waitCount: waitPromises.length,
  }),
);
