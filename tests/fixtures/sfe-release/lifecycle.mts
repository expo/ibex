import workerThreads from "node:worker_threads";

const mode = process.argv[2];

switch (mode) {
  case "exit-code":
    console.log("exit-code-ready");
    process.exitCode = 24;
    break;
  case "process-exit":
    console.log("process-exit-ready");
    process.exit(23);
    console.log("process-exit-returned");
    break;
  case "foreground-throw":
    throw new Error("foreground-lifecycle-fixture");
  case "background-throw":
    setTimeout(() => {
      throw new Error("background-lifecycle-fixture");
    }, 0);
    break;
  case "rejection":
    void Promise.reject(new Error("rejection-lifecycle-fixture"));
    break;
  case "unavailable-worker": {
    let message = "worker_threads.Worker unexpectedly succeeded";
    try {
      new workerThreads.Worker("ignored");
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    console.log(message);
    process.exitCode =
      message ===
      "worker_threads.Worker is not supported in this runtime. Use child_process instead."
        ? 0
        : 31;
    break;
  }
  case "signal":
    console.log("signal-ready");
    while (true) {}
  default:
    throw new Error(`unknown lifecycle fixture mode: ${mode}`);
}
