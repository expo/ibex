// Red-team for ENG-23112 (finding H): the timer fire loop scoped its
// `ScopedNativePrincipal` over `runNextTickQueue` AND `drainMicrotasks`, pinning
// g_native_callback_principal_id to the timer owner (root) while pending Promise
// microtasks drained. The ungranted dependency `evil-pkg` cannot read the secret
// directly: its DETACHED read — the runtime fs deputy passed straight to `.then`,
// with no evil frame live when the reaction runs — reaches kNoUserPrincipal and
// fails closed at the top-level poll. The attack is to have that same detached
// read drain INSIDE root's timer callback, where the leaked scope pinned root over
// the microtask drain, so the kNoUserPrincipal fallback resolved to root's
// authority and the read leaked — an escalation reachable in the default enforce
// mode with NO deputyClasses configured. The fix restricts the override to just
// the callback invocation, so the drain matches the top-level poll.
// @ref LLP 0013#phase-5 (ENG-23112)
var evil = require("evil-pkg");
var fs = require("fs");
var SECRET = process.env.SECRETPATH;

function sleep(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

var timerEvil = null;
var timerRoot = null;

async function main() {
  // (A) Positive control: root reads the secret DIRECTLY (its own frame live) ->
  // attributed to root, which is granted fs:read -> allowed. Proves the file,
  // grant, and path are wired so a CONTAINED below is a real capability denial,
  // not a broken read or a wrong path.
  try {
    console.log("direct: READ:" + String(fs.readFileSync(SECRET)).trim());
  } catch (_e) {
    console.log("direct: DENIED");
  }

  // (B) Baseline: the ungranted dependency's DETACHED read at the top level fails
  // closed (kNoUserPrincipal, no native override). Proves evil cannot read on its
  // own, so a leak in (C) is laundering through the timer scope, not evil's grant.
  console.log("evil-top-detached: " + (await evil.detachedRead(SECRET)));

  // (C) The attack: root schedules a timer whose callback invokes the ungranted
  // evil-pkg, which schedules its detached read. Pre-fix the leaked
  // ScopedNativePrincipal pinned root over the microtask drain, laundering the read
  // into root's authority (STOLEN). Post-fix the drain runs with no override ->
  // kNoUserPrincipal -> CONTAINED.
  setTimeout(function () {
    evil.detachedRead(SECRET).then(function (r) { timerEvil = r; });
  }, 0);
  await sleep(30);
  console.log("evil-timer-detached: " + (timerEvil || "PENDING"));

  // (D) No false-deny: root's OWN detached read scheduled across a timer stays
  // allowed (root's fs deputy carries root's authority, granted fs:read). The fix
  // closes only the no-user laundering path, not legitimate timer-scheduled work by
  // the owner.
  setTimeout(function () {
    Promise.resolve(SECRET).then(fs.readFileSync).then(
      function (buf) { timerRoot = "READ:" + String(buf).trim(); },
      function () { timerRoot = "DENIED"; }
    );
  }, 0);
  await sleep(30);
  console.log("root-timer-detached: " + (timerRoot || "PENDING"));
}

main();
