(function cleanupBuiltinEffectsOutputFixture(config) {
  "use strict";

  function completions() {
    if (
      !globalThis.__ibexBuiltinEffectsOutputCompletions ||
      typeof globalThis.__ibexBuiltinEffectsOutputCompletions !== "object"
    ) {
      globalThis.__ibexBuiltinEffectsOutputCompletions = Object.create(null);
    }
    return globalThis.__ibexBuiltinEffectsOutputCompletions;
  }
  function errorCode(error) {
    return error && typeof error.code === "string" && error.code.length > 0
      ? error.code
      : "ERR_IBEX_BUILTIN_EFFECTS_FIXTURE_CLEANUP";
  }

  var store = globalThis.__ibexBuiltinEffectsOutputFixtures;
  var fixture = store && store[config.fixtureKey];
  if (store) delete store[config.fixtureKey];
  if (!fixture) {
    return {
      kind: "fixture-cleanup-failure",
      completionToken: null,
      errorCode: "ERR_IBEX_BUILTIN_EFFECTS_FIXTURE_ABSENT",
    };
  }
  try {
    if (fixture.kind === "fd") {
      require("node:fs").closeSync(fixture.value);
      return {
        kind: "fixture-cleanup-completion",
        completionToken: null,
        errorCode: null,
      };
    }
    if (fixture.kind === "file-handle") {
      var completionToken =
        "builtin-effects-output-cleanup:" + config.fixtureKey;
      var completionStore = completions();
      delete completionStore[completionToken];
      fixture.value.close().then(
        function () {
          completionStore[completionToken] = {
            calls: 1,
            settled: "fulfilled",
          };
        },
        function (error) {
          completionStore[completionToken] = {
            calls: 1,
            settled: "rejected",
            errorCode: errorCode(error),
          };
        },
      );
      return {
        kind: "fixture-cleanup-completion",
        completionToken: completionToken,
        errorCode: null,
      };
    }
    throw new TypeError("unsupported filesystem live fixture kind");
  } catch (error) {
    return {
      kind: "fixture-cleanup-failure",
      completionToken: null,
      errorCode: errorCode(error),
    };
  }
})
