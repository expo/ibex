// @ref LLP 0013#mechanism-2 — compartment endowment conformance. Simulates the
// code the compartment transform emits (bare globals rewritten to
// `__compartments[<pkg>].<name>`) and asserts withholding vs endowment.
"use strict";
var reg = globalThis.__compartments;
if (!reg) {
  console.log("registry=missing");
} else {
  var evil = reg["evil-pkg"];
  console.log("evil.process=" + typeof evil.process); // withheld -> undefined
  console.log("evil.fetch=" + typeof evil.fetch);     // withheld -> undefined
  console.log("evil.Object=" + typeof evil.Object);   // shared  -> function
  console.log("evil.console=" + typeof evil.console); // shared  -> object

  var trusted = reg["trusted-net"];
  console.log("trusted.fetch=" + typeof trusted.fetch); // endowed (IBEX_ENDOW)
}
