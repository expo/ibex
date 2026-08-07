if (process.env.IBEX_TAMPER_SENTINEL === "1") {
  console.log("carrier-evaluated:value-cjs");
}

module.exports = { value: "commonjs" };
