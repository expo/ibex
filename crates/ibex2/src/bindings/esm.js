// The two runtime helpers ESM lowering needs.
//
// Kept to two, and both are interop rather than semantics: everything the ES
// module spec actually says is expressed by the lowered code itself.
(function (global) {
  "use strict";

  // `import d from './x'` where './x' is CommonJS. A CJS module has no
  // `default`, and treating its module.exports as one is the interop every
  // bundler converged on. The __esModule marker is how a lowered ES module
  // says "my default really is .default".
  global.__ibex2_default = function (module) {
    if (module && (module.__esModule || typeof module.default !== "undefined")) {
      return module.default;
    }
    return module;
  };

  // `export * from './x'`. Live, like every other export, and `default` is
  // deliberately excluded — the spec does not re-export it.
  //
  // forEach, not `for (const name of ...)`: on the pinned Hermes a for-of
  // `const` does NOT create a per-iteration binding, so every getter closes
  // over the LAST name and `export * from` republishes one value under every
  // key. forEach gives a fresh invocation per element, so the capture is
  // correct regardless. See LLP 0062 §5.
  global.__ibex2_export_all = function (target, source) {
    if (source === null || typeof source !== "object") return;
    Object.getOwnPropertyNames(source).forEach(function (name) {
      if (name === "default" || name === "__esModule") return;
      if (Object.prototype.hasOwnProperty.call(target, name)) return;
      Object.defineProperty(target, name, {
        get: function () {
          return source[name];
        },
        enumerable: true,
        configurable: true,
      });
    });
  };
})(globalThis);
