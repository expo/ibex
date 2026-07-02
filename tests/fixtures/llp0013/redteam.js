// @ref LLP 0013#phase-1 — the named red-team cases. Each attack prints
// "<name>: CONTAINED (...)" if it was stopped, or "<name>: NOT_CONTAINED (...)"
// if it succeeded. Under `--lockdown` every case must be CONTAINED. Without
// lockdown, the ambient-authority cases are NOT_CONTAINED (proving the attacks
// are real), while the host-tamper cases stay CONTAINED because the Phase 0
// escape-hatch seal runs in all modes.
"use strict";
var results = [];
function check(name, fn) {
  try {
    var r = fn();
    results.push(name + ": NOT_CONTAINED (" + r + ")");
  } catch (e) {
    results.push(name + ": CONTAINED (" + (e && e.name) + ")");
  }
}

// Recover the real global via a prototype-walk to the Function constructor.
check("recover-real-global", function () {
  var FnCtor = ({}).constructor.constructor;
  var realGlobal = FnCtor("return this")();
  return "got global: " + typeof realGlobal;
});

// Dynamic-code escape via the Function constructor.
check("dynamic-code-Function", function () {
  return (function () {}).constructor("return 42")();
});

// Dynamic-code escape via direct eval.
check("dynamic-code-eval", function () {
  return eval("40+2");
});

// Prototype patching (identity-theft vector): hijack Array.prototype.map.
check("prototype-patch-Array", function () {
  Array.prototype.map = function () { return "HIJACKED"; };
  return [1].map(function (x) { return x; });
});

// Object.prototype pollution.
check("proto-pollution", function () {
  Object.prototype.polluted = "yes";
  return ({}).polluted;
});

// Generator-function evaluator reachable via .constructor.
check("generator-evaluator", function () {
  var GenFn = (function* () {}).constructor;
  return typeof GenFn("yield 1");
});

// Host tampering: the module-attribution setter must be unreachable.
check("host-tamper-setActiveModuleId", function () {
  return globalThis.__exactSetActiveModuleId(0);
});

// Host tampering: the self-grant function must be unreachable.
check("host-tamper-grantCapability", function () {
  return globalThis.__exactGrantCapability(0, "fs:read:/");
});

for (var i = 0; i < results.length; i++) {
  console.log(results[i]);
}
