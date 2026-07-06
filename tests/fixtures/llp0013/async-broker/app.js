// @ref LLP 0013 — §dynamic permissions — acquisition is async (lives in the
// attenuator), the boundary check stays synchronous and consults resolved state.
var p = Ibex.permissions;
(async function () {
  console.log("before: " + p.status("network:fetch"));
  var ok = await p.acquire("network:fetch");
  console.log("acquired: " + ok + " after: " + p.status("network:fetch"));
  var no = await p.acquire("device:location");
  console.log("denied-acquire: " + no + " status: " + p.status("device:location"));
  p.broker = function () { return Promise.resolve(false); };
  p.revoke("network:fetch");
  var rejected = await p.acquire("network:fetch");
  console.log("broker-reject: " + rejected + " status: " + p.status("network:fetch"));
})();
