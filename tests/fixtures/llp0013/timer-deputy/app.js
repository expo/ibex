// Red-team for ENG-22759: the async-detached confused-deputy attack laundered
// through the HOST callback queues (setTimeout / process.nextTick / setImmediate)
// instead of the Promise microtask queue that patch 0008 already closed. evil
// arms the deputy and passes its read method RAW to a host timer, so the read
// runs detached (only the deputy's frame live). Schedule-time capture across the
// host queues (patch 0009) restores the ungranted scheduler and the deputy-class
// AND denies. The granted cases prove the capture does not false-deny legitimate
// async work. @ref LLP 0013#phase-5
var deputy = require("deputy-pkg");
var logger = require("logger-pkg");
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;

function sleep(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

async function main() {
  // (A) The app (root, trusted) drives the deputy DETACHED across a timer. The
  // scheduler captured at enqueue is root -> the detached read is allowed. Proves
  // schedule-time capture does not break the app's own async deputy use.
  deputy.arm(SECRET);
  deputy.takeLast();
  setTimeout(deputy.readArmed, 0);
  await sleep(30);
  var a = deputy.takeLast();
  console.log("app-timer-via-deputy: " + (a ? ("READ:" + a) : "DENIED"));

  // (B) A GRANTED third-party package runs its OWN timer continuation — the shape
  // a blunt "deny single-principal deputy-class op" fix would false-deny. The
  // scheduler equals the running principal (logger), so the stack collapses to
  // [logger] and the read is allowed.
  var b = await logger.readOwnViaTimer(SECRET);
  console.log("logger-timer-self: " + (b !== "DENIED" ? ("READ:" + b) : "DENIED"));

  // (C) A GRANTED package drives the deputy DETACHED across a timer. Both
  // principals in the chain (logger scheduler + deputy) are granted -> AND passes.
  var c = await logger.readViaDeputyTimer(SECRET);
  console.log("logger-timer-via-deputy: " + (c !== "DENIED" ? ("READ:" + c) : "DENIED"));

  // (D) The attack, across all three host channels: ungranted evil detaches the
  // deputy so its own frame is gone when the read runs. Schedule-time capture
  // restores evil as the scheduler -> the deputy-class AND denies on every channel.
  console.log("evil-timer-via-deputy: " + (await evil.stealViaTimer(SECRET)));
  console.log("evil-nexttick-via-deputy: " + (await evil.stealViaNextTick(SECRET)));
  console.log("evil-setimmediate-via-deputy: " + (await evil.stealViaSetImmediate(SECRET)));
}

main();
