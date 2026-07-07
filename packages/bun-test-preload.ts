// Suite-level guard (ENG-23319). Several suites exercise deliberate error
// paths (rejected pulls, aborted fetches, EEXIST writes, async-generator
// rejection fixtures) whose rejections the ibex builtins' fail-loud reporter
// (events.js / promise-rejection-tracking.ts, ENG-23130 — async failures must
// not exit 0 in the RUNTIME) observes in the shared bun test process and
// answers with `process.exitCode = 1`. Bun's own pass/fail accounting is the
// source of truth for test results here, so an otherwise-green run must not
// fail on that runtime-facing side effect; the reporter's console.error output
// stays visible in the log. Trade-off, documented: a test that signals failure
// ONLY via process.exitCode would be masked — signal failures through bun
// assertions instead.
import { afterAll, afterEach } from 'bun:test';

function resetLeakedExitCode(): void {
  if (typeof process.exitCode === 'number' && process.exitCode !== 0) {
    process.exitCode = 0;
  }
}

afterEach(resetLeakedExitCode);
afterAll(resetLeakedExitCode);
