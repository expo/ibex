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

  function __exactApplyVersionsPatch(target, patchedVersions) {
    if (!target || typeof target !== 'object') return false;
    try {
      var desc = Object.getOwnPropertyDescriptor(target, 'versions');
      if (!desc) {
        return false;
      }
      if (typeof desc.get === 'function' && desc.set === undefined) {
        try {
          Object.defineProperty(target, 'versions', {
            value: patchedVersions,
            writable: true,
            configurable: true,
            enumerable: !!desc.enumerable
          });
        } catch (err) {}
        try {
          target.versions = patchedVersions;
        } catch (err) {}
        return __exactIsProcessVersionsDataDescriptor(target);
      }
      if ('value' in desc && desc.writable === true && !desc.get) {
        return true;
      }
      try {
        Object.defineProperty(target, 'versions', {
          value: patchedVersions,
          writable: true,
          configurable: !!desc.configurable,
          enumerable: !!desc.enumerable
        });
        var patchedDesc = Object.getOwnPropertyDescriptor(target, 'versions');
        return !!(
          patchedDesc &&
          Object.prototype.hasOwnProperty.call(patchedDesc, 'value') &&
          patchedDesc.writable === true &&
          patchedDesc.set === undefined
        );
      } catch (err) {}
      try {
        target.versions = patchedVersions;
        var patchedDescAfterAssign = Object.getOwnPropertyDescriptor(target, 'versions');
        return !!(
          patchedDescAfterAssign &&
          Object.prototype.hasOwnProperty.call(patchedDescAfterAssign, 'value') &&
          patchedDescAfterAssign.writable === true &&
          patchedDescAfterAssign.set === undefined
        );
      } catch (err) {}
    } catch (err) {}
    return false;
  }

  function __exactIsProcessVersionsDataDescriptor(target) {
    try {
      var finalDesc = Object.getOwnPropertyDescriptor(target, 'versions');
      if (!finalDesc) return false;
      if ('value' in finalDesc) {
        return finalDesc.writable === true;
      }
    } catch (e) {}
    return false;
  }

  (function __exactPatchProcessVersions() {
    var patchedVersions = {
      node: process.versions && process.versions.node ? process.versions.node : '24.13.1',
      v8: process.versions && process.versions.v8 ? process.versions.v8 : '0.0.0',
      uv: process.versions && process.versions.uv ? process.versions.uv : '0.0.0',
      zlib: process.versions && process.versions.zlib ? process.versions.zlib : '1.3.1',
      brotli: process.versions && process.versions.brotli ? process.versions.brotli : '0.0.0',
      ares: process.versions && process.versions.ares ? process.versions.ares : '0.0.0',
      modules: process.versions && process.versions.modules ? process.versions.modules : '127',
      nghttp2: process.versions && process.versions.nghttp2 ? process.versions.nghttp2 : '0.0.0',
      napi: process.versions && process.versions.napi ? process.versions.napi : '9',
      llhttp: process.versions && process.versions.llhttp ? process.versions.llhttp : '0.0.0',
      uvwasi: process.versions && process.versions.uvwasi ? process.versions.uvwasi : '0.0.0',
      unicode: process.versions && process.versions.unicode ? process.versions.unicode : '15.1',
      openssl: process.versions && process.versions.openssl ? process.versions.openssl : '3.0.0',
      hermes: process.versions && process.versions.hermes ? process.versions.hermes : '0.12.0',
      exact: process.versions && process.versions.exact ? process.versions.exact : '0.1.0'
    };

    try {
      __exactApplyVersionsPatch(process, patchedVersions);
    } catch (err) {}

    try {
      var processVersionProto = Object.getPrototypeOf(process);
      var patchTarget = processVersionProto;
      while (patchTarget && patchTarget !== Object.prototype && typeof patchTarget === 'object') {
        if (__exactApplyVersionsPatch(patchTarget, patchedVersions)) {
          processVersionProto = patchTarget;
          break;
        }
        patchTarget = Object.getPrototypeOf(patchTarget);
      }
      if (processVersionProto && typeof processVersionProto === 'object' && processVersionProto !== Object.prototype) {
        var finalVersionsDesc = Object.getOwnPropertyDescriptor(processVersionProto, 'versions');
        if (!__exactIsProcessVersionsDataDescriptor(processVersionProto)) {
          try {
            Object.defineProperty(processVersionProto, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: true,
              enumerable: !!(finalVersionsDesc && finalVersionsDesc.enumerable)
            });
          } catch (err) {}
          if (!__exactIsProcessVersionsDataDescriptor(processVersionProto)) {
            try {
              var patchedVersionProto = Object.create(processVersionProto);
              Object.defineProperty(patchedVersionProto, 'versions', {
                value: patchedVersions,
                writable: true,
                configurable: true,
                enumerable: false
              });
              Object.setPrototypeOf(process, patchedVersionProto);
            } catch (err2) {}
          }
        }
        if (!__exactIsProcessVersionsDataDescriptor(processVersionProto)) {
          try {
            Object.defineProperty(process, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: true,
              enumerable: true
            });
          } catch (err3) {}
        }
      }
    } catch (err) {}
  })();

  (function() {
    var processProto = Object.getPrototypeOf(process);
    if (
      !processProto || typeof processProto !== 'object' ||
      processProto === Object.prototype
    ) {
      return;
    }
    var versionsValue;
    try {
      versionsValue = process.versions;
    } catch (e) {
      versionsValue = null;
    }
    if (!versionsValue || typeof versionsValue !== 'object') {
      return;
    }
    var versionsDesc;
    try {
      versionsDesc = Object.getOwnPropertyDescriptor(processProto, 'versions');
    } catch (e) {}
    var needsPatch = true;
    if (versionsDesc && ('value' in versionsDesc) && versionsDesc.writable === true) {
      needsPatch = false;
    }
    if (!needsPatch) {
      return;
    }
    try {
      Object.defineProperty(processProto, 'versions', {
        value: versionsValue,
        writable: true,
        configurable: true,
        enumerable: true
      });
      var patchedVersionsDesc = Object.getOwnPropertyDescriptor(processProto, 'versions');
      if (
        patchedVersionsDesc &&
        patchedVersionsDesc.writable === true &&
        Object.prototype.hasOwnProperty.call(patchedVersionsDesc, 'value')
      ) {
        return;
      }
    } catch (e) {
      try {
        processProto.versions = versionsValue;
      } catch (e2) {}
    }

    try {
      var patchedVersionProto = Object.create(processProto);
      Object.defineProperty(patchedVersionProto, 'versions', {
        value: versionsValue,
        writable: true,
        configurable: true,
        enumerable: true
      });
      Object.setPrototypeOf(process, patchedVersionProto);
      return;
    } catch (e3) {}
    try {
      var finalProtoDesc = Object.getOwnPropertyDescriptor(processProto, 'versions');
      if (!finalProtoDesc || finalProtoDesc.get) {
        processProto.versions = versionsValue;
      }
    } catch (e4) {}
  })();

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

  (function() {
    var processProto = Object.getPrototypeOf(process);
    if (
      !processProto || typeof processProto !== 'object' ||
      processProto === Object.prototype
    ) {
      return;
    }
    var keys = [];
    try {
      keys = Object.keys(process);
    } catch (e) {
      return;
    }
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var desc;
      try {
        desc = Object.getOwnPropertyDescriptor(processProto, key);
      } catch (e) {}
      if (!desc) {
        continue;
      }
      var hasValue = Object.prototype.hasOwnProperty.call(desc, 'value');
      if (
        (!hasValue && typeof desc.get === 'function' && !desc.set) ||
        (hasValue && desc.writable !== true)
      ) {
        var value;
        try {
          value = process[key];
        } catch (e) {}
        try {
          Object.defineProperty(processProto, key, {
            value: value,
            writable: true,
            enumerable: !!desc.enumerable,
            configurable: !!desc.configurable
          });
          continue;
        } catch (e) {
          try {
            processProto[key] = value;
          } catch (e2) {}
        }
      }
    }
  })();

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

  (function() {
    var execPathValue;
    try {
      execPathValue = process.execPath;
    } catch (e) {}
    if (execPathValue === undefined) {
      execPathValue = '';
    }
    function __exactDefineExecPath(target, value) {
      if (!target || typeof target !== 'object') {
        return false;
      }
      try {
        var desc = Object.getOwnPropertyDescriptor(target, 'execPath');
        if (!desc || !('value' in desc) || desc.writable !== true) {
          Object.defineProperty(target, 'execPath', {
            value: value,
            writable: true,
            enumerable: true,
            configurable: true
          });
          return true;
        }
      } catch (e) {}
      try {
        target.execPath = value;
        return true;
      } catch (e) {}
      return false;
    }
    __exactDefineExecPath(process, execPathValue);
    var processProto = Object.getPrototypeOf(process);
    if (
      processProto &&
      processProto !== Object.prototype &&
      processProto !== process &&
      typeof processProto === 'object'
    ) {
      __exactDefineExecPath(processProto, execPathValue);
    }
  })();

  if (typeof process.emitWarning !== 'function') {
    try {
      process.emitWarning = function(warning) {
        var warningObject = warning;
        if (!(warning instanceof Error)) {
          warningObject = new Error(typeof warning === 'string' ? warning : ''); 
          warningObject.name = 'Warning';
          warningObject.code = undefined;
          if (typeof warning === 'object' && warning && warning.message) {
            warningObject.message = warning.message;
          } else if (warning && warning.code) {
            warningObject.code = warning.code;
          }
        }
        if (typeof warningObject.code !== 'string' && warning && warning.code) {
          warningObject.code = warning.code;
        }
        if (typeof warningObject.name !== 'string' && warning && warning.name) {
          warningObject.name = warning.name;
        }
        if (typeof warningObject.message !== 'string' && warning && warning.message) {
          warningObject.message = warning.message;
        }
        try {
          if (typeof process.emit === 'function') {
            process.emit('warning', warningObject);
          }
        } catch (e) {}
      };
    } catch (e) {}
  }

  // Final fallback: ensure process.versions has openssl and other required fields.
  // This runs at the very end of process-compat-fix, after all other patching attempts.
  (function __exactFinalVersionsFix() {
    globalThis.__exactFinalVersionsFixRan = 1;
    try {
      // Get the current versions value, wherever it lives (own or prototype getter)
      var curVersions = process.versions;
      if (!curVersions || typeof curVersions !== 'object') curVersions = {};
      // Build a plain new object with all current values plus our required defaults
      var finalVersions = {};
      var keys = Object.keys(curVersions);
      for (var i = 0; i < keys.length; i++) {
        try { finalVersions[keys[i]] = curVersions[keys[i]]; } catch(e) {}
      }
      if (!finalVersions.node) finalVersions.node = '24.13.1';
      if (!finalVersions.openssl) finalVersions.openssl = '3.0.0';
      if (!finalVersions.v8) finalVersions.v8 = '0.0.0';
      if (!finalVersions.uv) finalVersions.uv = '0.0.0';
      if (!finalVersions.zlib) finalVersions.zlib = '1.3.1';
      if (!finalVersions.modules) finalVersions.modules = '127';
      if (!finalVersions.napi) finalVersions.napi = '9';
      if (!finalVersions.hermes) finalVersions.hermes = '0.12.0';
      if (!finalVersions.exact) finalVersions.exact = '0.1.0';
      globalThis.__exactFinalVersionsObj = finalVersions;
      globalThis.__exactFinalVersionsOpenssl = finalVersions.openssl;

      // Try defining directly on process as own property
      try {
        Object.defineProperty(process, 'versions', {
          value: finalVersions,
          writable: true,
          configurable: true,
          enumerable: true
        });
        globalThis.__exactFinalVersionsDefineOK = 1;
      } catch(e) {
        globalThis.__exactFinalVersionsDefineOK = 'FAIL:' + e.message;
      }
      globalThis.__exactFinalVersionsSame = (process.versions === finalVersions) ? 1 : 0;
      globalThis.__exactFinalVersionsOpensslAfter = process.versions ? process.versions.openssl : 'NO_VERSIONS';
      if (process.versions === finalVersions) return;

      // Try on the prototype
      var p = Object.getPrototypeOf(process);
      if (p && p !== Object.prototype) {
        try {
          Object.defineProperty(p, 'versions', {
            value: finalVersions,
            writable: true,
            configurable: true,
            enumerable: false
          });
          globalThis.__exactFinalVersionsProtoOK = 1;
        } catch(e) {
          globalThis.__exactFinalVersionsProtoOK = 'FAIL:' + e.message;
        }
        if (process.versions === finalVersions) return;

        // Insert a new prototype
        try {
          var newProto = Object.create(p);
          Object.defineProperty(newProto, 'versions', {
            value: finalVersions,
            writable: true,
            configurable: true,
            enumerable: false
          });
          Object.setPrototypeOf(process, newProto);
          globalThis.__exactFinalVersionsNewProtoOK = 1;
        } catch(e) {
          globalThis.__exactFinalVersionsNewProtoOK = 'FAIL:' + e.message;
        }
      }
    } catch(e) {
      globalThis.__exactFinalVersionsError = e.message;
    }
  })();

  // Preserve process prototype behavior while ensuring enumerable accessor-only
  // keys can be copied onto process-like objects in user tests.
})();
