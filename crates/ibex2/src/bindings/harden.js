// The LLP 0062 §3/R4 intrinsic freeze, run after the standard library is
// installed and before any module code.
//
// Three properties this walk must have, all of which the retired native
// __exactDeepFreeze also had: it reads property DESCRIPTORS so getters are not
// invoked, it is ITERATIVE so a deep graph cannot hit a native stack cap, and
// it tracks VISITED so cycles terminate.
(function () {
  "use strict";
  const seen = new Set();
  const queue = [globalThis];
  while (queue.length) {
    const obj = queue.pop();
    if (obj === null || (typeof obj !== "object" && typeof obj !== "function")) continue;
    if (seen.has(obj)) continue;
    seen.add(obj);
    try { Object.freeze(obj); } catch (e) {}
    const names = Object.getOwnPropertyNames(obj);
    for (let i = 0; i < names.length; i++) {
      let d;
      try { d = Object.getOwnPropertyDescriptor(obj, names[i]); } catch (e) { continue; }
      if (!d) continue;
      if ("value" in d) queue.push(d.value);
      else { queue.push(d.get); queue.push(d.set); }
    }
    try { queue.push(Object.getPrototypeOf(obj)); } catch (e) {}
  }
})();
