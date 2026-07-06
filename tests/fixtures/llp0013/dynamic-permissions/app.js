// @ref LLP 0013 — §dynamic permissions — the runtime permission surface. The
// static policy is the ceiling; a prompt moves the floor within it, never past.
var p = Ibex.permissions;
// network:fetch is in the ceiling but not statically granted -> prompt.
console.log("fetch-before: " + p.status("network:fetch"));
console.log("fetch-request: " + p.request("network:fetch")); // user approves
console.log("fetch-after: " + p.status("network:fetch"));     // now granted
// device:location is NOT in the ceiling and not granted -> denied; a runtime
// request must fail (a dynamic grant can never exceed the static ceiling).
console.log("loc-status: " + p.status("device:location"));
console.log("loc-request: " + p.request("device:location"));
// revoke moves the floor back down.
p.revoke("network:fetch");
console.log("fetch-revoked: " + p.status("network:fetch"));
