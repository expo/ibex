// @ref LLP 0013#mechanism-1 — lockdown conformance: the harness must stay
// usable after hardening. Prints a line per property so the test can assert.
"use strict";
console.log("lockedDown=" + (globalThis.__ibexLockedDown === true));

// Normal library code keeps working (intrinsics stay shared).
var doubled = [1, 2, 3].map(function (x) { return x * 2; });
console.log("mapWorks=" + (doubled.join(",") === "2,4,6"));

// instanceof / classes across the shared intrinsics keep working.
console.log("instanceofWorks=" + ([] instanceof Array));

// A frozen prototype cannot be mutated (strict mode throws).
var frozeThrew = false;
try {
  Array.prototype.push = function () {};
} catch (e) {
  frozeThrew = true;
}
console.log("frozenProtoThrows=" + frozeThrew);

// The compartment registry exists under lockdown.
console.log("registry=" + (typeof globalThis.__compartments === "object"));
