(function() {
  globalThis.__exactProcessCompatFixRan = 1;
  globalThis.__exactProcessCompatFixSawProcess = (typeof process === 'object' && process !== null);
  if (!globalThis.__exactProcessCompatFixSawProcess) return;
  var configValue = process.config;
  if (!configValue || typeof configValue !== 'object' || !configValue.variables) {
    var configValueObject = { target_defaults: {}, variables: {} };
    try {
      Object.defineProperty(process, 'config', {
        value: configValueObject,
        writable: true,
        enumerable: true,
        configurable: true
      });
    } catch (e) {
      process.config = configValueObject;
    }

    if (!process.config || typeof process.config !== 'object' || !process.config.variables) {
      var proto = Object.getPrototypeOf(process);
      if (proto && typeof proto === 'object') {
        try {
          Object.defineProperty(proto, 'config', {
            value: configValueObject,
            writable: true,
            enumerable: false,
            configurable: true
          });
        } catch (e2) {
          proto.config = configValueObject;
        }
      }
    }
  }
})();
