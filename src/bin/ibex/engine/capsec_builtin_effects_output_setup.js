(function setupBuiltinEffectsOutputFixture(config) {
  "use strict";

  var completionToken = null;
  function completions() {
    if (
      !globalThis.__ibexBuiltinEffectsOutputCompletions ||
      typeof globalThis.__ibexBuiltinEffectsOutputCompletions !== "object"
    ) {
      globalThis.__ibexBuiltinEffectsOutputCompletions = Object.create(null);
    }
    return globalThis.__ibexBuiltinEffectsOutputCompletions;
  }
  function fixtures() {
    if (
      !globalThis.__ibexBuiltinEffectsOutputFixtures ||
      typeof globalThis.__ibexBuiltinEffectsOutputFixtures !== "object"
    ) {
      globalThis.__ibexBuiltinEffectsOutputFixtures = Object.create(null);
    }
    return globalThis.__ibexBuiltinEffectsOutputFixtures;
  }
  function errorCode(error) {
    return error && typeof error.code === "string" && error.code.length > 0
      ? error.code
      : "ERR_IBEX_BUILTIN_EFFECTS_FIXTURE_SETUP";
  }

  try {
    if (
      !config ||
      config.kind !== "source-authored-filesystem-live-fixture" ||
      (config.fixtureKind !== "fd" && config.fixtureKind !== "file-handle")
    ) {
      throw new TypeError("invalid filesystem live fixture setup");
    }
    var fixtureStore = fixtures();
    delete fixtureStore[config.fixtureKey];
    var moduleValue = require(config.moduleSpecifier);
    if (config.operation === "open-sync" && config.fixtureKind === "fd") {
      var fd = moduleValue.openSync(config.path, config.flags);
      fixtureStore[config.fixtureKey] = { kind: "fd", value: fd };
      return {
        kind: "fixture-setup-completion",
        fixtureKind: config.fixtureKind,
        fixtureKey: config.fixtureKey,
        completionToken: null,
        rawOutput: {
          kind: "return",
          rawValueShape: "number",
          value: null,
          errorCode: null,
        },
      };
    }
    if (
      config.operation === "open-promise" &&
      config.fixtureKind === "file-handle"
    ) {
      completionToken = "builtin-effects-output-setup:" + config.fixtureKey;
      var completionStore = completions();
      delete completionStore[completionToken];
      var promise = moduleValue.open(config.path, config.flags);
      promise.then(
        function (handle) {
          fixtureStore[config.fixtureKey] = {
            kind: "file-handle",
            value: handle,
          };
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
        kind: "fixture-setup-completion",
        fixtureKind: config.fixtureKind,
        fixtureKey: config.fixtureKey,
        completionToken: completionToken,
        rawOutput: {
          kind: "return",
          rawValueShape: "object",
          value: null,
          errorCode: null,
        },
      };
    }
    throw new TypeError("unsupported filesystem live fixture operation");
  } catch (error) {
    return {
      kind: "fixture-setup-failure",
      fixtureKind: config && config.fixtureKind,
      fixtureKey: config && config.fixtureKey,
      completionToken: completionToken,
      rawOutput: {
        kind: "throw",
        rawValueShape: "throw",
        value: null,
        errorCode: errorCode(error),
      },
    };
  }
})
