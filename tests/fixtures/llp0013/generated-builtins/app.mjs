// @ref LLP 0014#the-generated-artifact — first-party root code. Neither package
// is granted anything; the generated policy fences their builtin imports by
// default. `os-user` statically imports `node:os`, so the generator observes it
// and allowlists it (the import works). `sneaky-os` reaches for `os` through a
// computed specifier the generator cannot see, so it stays denied — a builtin
// not in the generated allowlist is refused (ENG-22683).
import osUser from "os-user";
import sneaky from "sneaky-os";

console.log("os-user:   " + osUser());
console.log("sneaky-os: " + sneaky());
