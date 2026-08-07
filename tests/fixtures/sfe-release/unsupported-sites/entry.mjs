import "./dependency.cjs";

const selected = "./unreached.mjs";
if (false) {
  await import(selected);
}
if (false) {
  await import(selected, { with: { mystery: "value" } });
}

console.log("unsupported-sites-ok");
