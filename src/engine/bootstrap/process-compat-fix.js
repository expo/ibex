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

  // Add missing process methods for Node.js compat
  if (typeof process.assert !== 'function') {
    try {
      process.assert = function(value, message) {
        if (!value) {
          throw new Error(message || 'assertion error');
        }
      };
    } catch(e) {}
  }

  if (typeof process.availableMemory !== 'function') {
    try {
      process.availableMemory = function() {
        return 2 * 1024 * 1024 * 1024;
      };
    } catch(e) {}
  }

  if (typeof process.constrainedMemory !== 'function') {
    try {
      process.constrainedMemory = function() {
        return 0;
      };
    } catch(e) {}
  }

  if (typeof process.cpuUsage !== 'function') {
    try {
      process.cpuUsage = function(previousValue) {
        var result = { user: 0, system: 0 };
        if (previousValue) {
          result.user -= previousValue.user;
          result.system -= previousValue.system;
        }
        return result;
      };
    } catch(e) {}
  }

  if (typeof process.resourceUsage !== 'function') {
    try {
      process.resourceUsage = function() {
        return {
          userCPUTime: 0, systemCPUTime: 0,
          maxRSS: 0, sharedMemorySize: 0,
          unsharedDataSize: 0, unsharedStackSize: 0,
          minorPageFault: 0, majorPageFault: 0,
          swappedOut: 0, fsRead: 0, fsWrite: 0,
          ipcSent: 0, ipcReceived: 0,
          signalsCount: 0, voluntaryContextSwitches: 0,
          involuntaryContextSwitches: 0
        };
      };
    } catch(e) {}
  }

  if (!process.report) {
    try {
      process.report = {
        directory: '',
        filename: '',
        signal: 'SIGUSR2',
        reportOnFatalError: false,
        reportOnSignal: false,
        reportOnUncaughtException: false,
        getReport: function() { return {}; },
        writeReport: function() { return ''; }
      };
    } catch(e) {}
  }

  // Note: Do NOT patch the prototype of process — it may be Object.prototype
  // which would pollute all object property lookups globally.
})();
