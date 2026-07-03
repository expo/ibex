var deputy = require("deputy-pkg");
var logger = require("logger-pkg");
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;

async function main() {
  // (A) The app (root, trusted) schedules the deputy across a microtask. The
  // scheduler captured at enqueue is root → the detached read is allowed. Proves
  // schedule-time capture does not break the app's own async deputy use.
  try {
    var a = await Promise.resolve(SECRET).then(deputy.readFor);
    console.log("app-async-via-deputy: READ:" + a);
  } catch (e) {
    console.log("app-async-via-deputy: DENIED");
  }

  // (B) A GRANTED third-party package runs its OWN async continuation — the shape
  // a blunt "deny single-principal deputy-class op" fix would false-deny. The
  // scheduler equals the running principal (logger), so the stack collapses to
  // [logger] and the read is allowed.
  try {
    var b = await logger.readOwnAsync(SECRET);
    console.log("logger-async-self: READ:" + b);
  } catch (e) {
    console.log("logger-async-self: DENIED");
  }

  // (C) A GRANTED package drives the deputy across a microtask. Both principals in
  // the chain (logger scheduler + deputy) are granted → the AND passes.
  try {
    var c = await logger.readViaDeputyAsync(SECRET);
    console.log("logger-async-via-deputy: READ:" + c);
  } catch (e) {
    console.log("logger-async-via-deputy: DENIED");
  }

  // (D) The attack (ENG-22631): ungranted evil DETACHES the deputy across a
  // microtask so its own frame is gone when the read runs. Schedule-time capture
  // restores evil as the scheduler → the deputy-class AND denies.
  console.log("evil-async-via-deputy: " + (await evil.stealAsync(SECRET)));
}

main();
