import http2 from "node:http2";
import { Session } from "node:inspector";
import { WASI } from "node:wasi";
import workerThreads from "node:worker_threads";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function captureFailure(operation: () => void): string {
  try {
    operation();
    return "unexpected success";
  } catch (error) {
    return errorMessage(error);
  }
}

const http2Message = captureFailure(() => http2.createServer());
const inspectorMessage = await new Promise<string>((resolve) => {
  Session.prototype.post.call({}, "Runtime.enable", (error: unknown) =>
    resolve(errorMessage(error)),
  );
});
const wasiMessage = captureFailure(() => WASI.prototype.start.call({}, {}));
const workerMessage = captureFailure(() => new workerThreads.Worker("ignored"));

const observed = [
  `http2=${http2Message}`,
  `inspector=${inspectorMessage}`,
  `wasi=${wasiMessage}`,
  `workers=${workerMessage}`,
];
const expected = [
  "http2=http2.createServer is not supported in this runtime without native HTTP/2 support",
  "inspector=Inspector is not available in this runtime",
  "wasi=WASI is not supported in this runtime",
  "workers=worker_threads.Worker is not supported in this runtime. Use child_process instead.",
];

for (const line of observed) console.log(line);
process.exitCode =
  observed.length === expected.length &&
  observed.every((line, index) => line === expected[index])
    ? 0
    : 32;
