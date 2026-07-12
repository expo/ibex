(function() {
  if (globalThis.__exactRequire) {
    return;
  }
  var g = globalThis;
  // @ref LLP 0013#phase-0 — capture the module-attribution setter into loader
  // closure scope so the escape-hatch global (`__exactSetActiveModuleId`) can be
  // deleted at end-of-bootstrap. JS control flow must not be able to impersonate
  // another module by calling the setter; the loader is its only legitimate
  // caller, so the private capture keeps attribution working after the seal.
  var __privSetActiveModuleId = (typeof g.__exactSetActiveModuleId === 'function')
    ? g.__exactSetActiveModuleId
    : null;
  // @ref LLP 0013#mechanism-1 — capture the real Function constructor before
  // lockdown tames the intrinsic evaluators. The loader is a trusted principal
  // and legitimately needs to compile CommonJS module bodies; package code that
  // reaches `({}).constructor.constructor` gets the tamed (throwing) form.
  var __privFunction = Function;
  // @ref LLP 0013#mechanism-3 — capture the frame-attribution bridge before the
  // end-of-bootstrap seal deletes these globals. The loader is the only
  // legitimate caller: it labels each package's Domain with a capability
  // principal so host-boundary checks resolve to the true executing package,
  // which JS cannot forge. Null on engines without the carried patch stack.
  var __privSetPendingPackageId = (typeof g.__exactSetPendingPackageId === 'function')
    ? g.__exactSetPendingPackageId
    : null;
  var __privRegisterPackage = (typeof g.__exactRegisterPackage === 'function')
    ? g.__exactRegisterPackage
    : null;
  // @ref LLP 0013#policy — the import-graph gate (Policy surface 3). Captured
  // privately so the check survives the end-of-bootstrap seal; the loader is its
  // only caller.
  var __privCheckImport = (typeof g.__exactCheckImport === 'function')
    ? g.__exactCheckImport
    : null;
  // @ref LLP 0013#mechanism-2 — (Phase 3) — native compartment binder. Sets a
  // compiled function's Domain compartment global so bare-global references in a
  // package resolve natively through its compartment (no build-time rewrite).
  // Powerful (setting a Domain's compartment could escape it), so captured
  // privately and deleted at the seal; the loader is its only caller.
  var __privSetCompartmentFor = (typeof g.__exactSetCompartmentFor === 'function')
    ? g.__exactSetCompartmentFor
    : null;
  var __privBarePackageName = (typeof g.__ibexBarePackageName === 'function')
    ? g.__ibexBarePackageName
    : function (identity) { return identity; };
  // The canonical runtime identity for a resolved module: the package name plus
  // its resolved version (`name@version`) when the host reported one, else the
  // bare name. Coexisting versions of one package therefore get distinct
  // principals, compartments, and endowment buckets, while the bare name stays
  // the policy selector that survives version bumps. @ref LLP 0013#resolved-questions
  // (ENG-22621)
  function packageIdentityFor(name, record) {
    if (!name) return null;
    var version = record && record.pkgVersion;
    return version ? name + '@' + version : name;
  }
  function normalizeRecordPath(p) {
    return typeof p === 'string' ? p.replace(/\\/g, '/').replace(/\/+$/, '') : null;
  }
  function packageRootForRecord(record) {
    return record && typeof record.pkgRoot === 'string'
      ? normalizeRecordPath(record.pkgRoot)
      : null;
  }
  // Prefer resolver-owned package metadata over path-shape inference. A linked
  // dependency may resolve to a real path outside node_modules; the first bare
  // import carries pkgName/pkgRoot from the resolver, and same-root relative
  // imports inherit that package identity from their parent. Path parsing remains
  // only a fallback for older records and generated per-package chunks.
  // @ref LLP 0014#the-grant-channel — package-vs-root classification decides
  // whether grant syntax is trusted root-authored policy input.
  function packageNameForRecord(record, parent) {
    if (record && typeof record.pkgName === 'string' && record.pkgName) {
      return record.pkgName;
    }
    var root = packageRootForRecord(record);
    if (root && parent && parent.__exactPackageRoot === root && parent.__exactPackageName) {
      return parent.__exactPackageName;
    }
    return packageNameFromPath(record && (record.path || record.id));
  }
  // The per-package compartment global for a resolved module, or null when it
  // should resolve against the real global (root / builtins / no registry).
  function compartmentForRecord(record, parent) {
    if (!__privSetCompartmentFor) return null;
    var registry = g.__compartments;
    if (!registry) return null;
    var name = packageNameForRecord(record, parent);
    if (!name) return null;
    // Key by the version-qualified identity so two installed versions never
    // share one mutable compartment global (ENG-22621). Name-level endowment
    // entries still apply via the registry's bare-name fallback (isEndowed).
    var identity = packageIdentityFor(name, record);
    try { return registry[identity] || null; } catch (e) { return null; }
  }
  // Principal ids assigned per package name (0 = first-party / trusted root).
  var __packagePrincipals = Object.create(null);
  var __nextPackagePrincipal = 1;
  // The reserved runtime principal (kept in sync with kRuntimePackageId in
  // Hermes' CapabilityAttribution.cpp): builtin modules (node:fs, node:path, …)
  // are trusted deputies whose Domains attribution sees through to the caller.
  var __runtimePrincipal = 0xFFFFFFFF;
  var __pkgChunkPrefix = '__ibexpkg__';
  // Whether a module path's basename claims to be a per-package bundle chunk
  // (`__ibexpkg__*`). The claim is only *trusted* when the file also lives in
  // the chunk output dir (see packageNameFromPath); this predicate lets
  // packagePrincipalFor refuse root for a chunk-claiming file that does not
  // resolve to a real package. (ENG-22624)
  function basenameClaimsChunk(p) {
    if (typeof p !== 'string') return false;
    var np = p.replace(/\\/g, '/');
    var slash = np.lastIndexOf('/');
    var base = slash === -1 ? np : np.slice(slash + 1);
    return base.indexOf(__pkgChunkPrefix) === 0;
  }
  // Derive the npm package selector from a resolved module path: the segment
  // after the last `node_modules/` (two segments for an @scope). Returns null
  // for first-party / workspace code, which stays the trusted root principal.
  // @ref LLP 0013#resolved-questions — (package name is the policy selector)
  function packageNameFromPath(p) {
    if (typeof p !== 'string') return null;
    // Normalize Windows separators before any marker detection. Runtime module
    // paths arrive from Rust PathBuf::to_string_lossy(), which emits backslashes
    // on Windows, so `C:\app\node_modules\evil\index.js` must still classify as
    // package code (else it gets root principal 0). (ENG-22619)
    p = p.replace(/\\/g, '/');
    // @ref LLP 0013#mechanism-3 — per-package bundle chunks (IBEX_PER_PACKAGE_CHUNKS)
    // are named `__ibexpkg__<encoded package>` and the chunk basename is the
    // authoritative principal. Trust it ONLY when the file physically resides in
    // the per-package-chunk output dir (`__exactChunkDir`): otherwise a
    // dependency could forge any principal — even root — by shipping a file
    // named `__ibexpkg__*` and requiring it. (ENG-22624)
    var slash = p.lastIndexOf('/');
    var base = slash === -1 ? p : p.slice(slash + 1);
    var dir = slash === -1 ? '' : p.slice(0, slash);
    if (base.indexOf(__pkgChunkPrefix) === 0 && g.__exactChunkDir) {
      var chunkDir = String(g.__exactChunkDir).replace(/\\/g, '/').replace(/\/+$/, '');
      if (dir.replace(/\/+$/, '') === chunkDir) {
        // Strip only the `.js` extension the chunk template adds. There is no
        // `[hash]` suffix in the chunk name, so do NOT strip a trailing `.<hex>`
        // run — that corrupts legit hex-tailed names like `foo.cafe`. (ENG-22641)
        var enc = base.slice(__pkgChunkPrefix.length).replace(/\.js$/, '');
        if (enc) return enc.split('__SLASH__').join('/');
        // Empty decoded name: an invalid chunk. Fall through — packagePrincipalFor
        // refuses to hand a chunk-claiming file the root principal. (ENG-22624)
      }
    }
    var marker = 'node_modules/';
    var idx = p.lastIndexOf(marker);
    if (idx === -1) return null;
    var rest = p.slice(idx + marker.length);
    var parts = rest.split('/');
    if (!parts.length || !parts[0]) return null;
    if (parts[0].charAt(0) === '@' && parts.length >= 2) {
      return parts[0] + '/' + parts[1];
    }
    return parts[0];
  }
  // Allocate (and register with the host, once) the capability principal id for
  // the package a module belongs to. @ref LLP 0013#mechanism-3
  function packagePrincipalFor(record, parent) {
    // Builtin modules are trusted runtime deputies (require('fs') is a JS shim
    // over the host functions); mark them so a package's host access through
    // them is attributed to the package, not laundered into root.
    if (record && record.kind === 'builtin') return __runtimePrincipal;
    var raw = record && (record.path || record.id);
    var name = packageNameForRecord(record, parent);
    if (!name) {
      // A file whose basename claims to be a per-package chunk (`__ibexpkg__*`)
      // but did not resolve to a real package name must never be attributed to
      // root — that is the forge ENG-22624 closes. Hand it an isolated,
      // never-registered quarantine principal instead (the host has no grants
      // for it, so it default-denies under enforce). Genuine chunks in the
      // chunk dir always resolve to a name and never reach this branch.
      if (basenameClaimsChunk(raw)) {
        return __nextPackagePrincipal++;
      }
      return 0;
    }
    // Key the principal by the version-qualified identity so two coexisting
    // versions get separate principals; register the **bare** name as the policy
    // selector and the identity as the locator, so host policy lookup consults
    // `name@version` before `name` (selector precedence, capability.rs::selectors).
    // `name` here is the bare package name for the unbundled path, but the
    // decoded chunk identity (`name@version`) for the bundled per-package-chunk
    // path — so derive both from the identity uniformly. @ref LLP 0013#resolved-questions
    // (ENG-22621)
    var identity = packageIdentityFor(name, record);
    var selector = __privBarePackageName(identity);
    var existing = __packagePrincipals[identity];
    if (existing) return existing;
    var id = __nextPackagePrincipal++;
    __packagePrincipals[identity] = id;
    if (__privRegisterPackage) {
      try {
        __privRegisterPackage(id, selector, identity, record && record.pkgIntegrity);
      } catch (e) {}
    }
    return id;
  }
  // Compile a module body, labelling the fresh Domain it creates with the
  // owning package's principal so frame-derived attribution is accurate even
  // for callbacks that run long after evaluation returns. One-shot: the pending
  // id is consumed by the engine when it creates the Domain.
  // @ref LLP 0013#mechanism-3
  function compileModuleBody(packagePrincipal, compartment, source) {
    if (__privSetPendingPackageId) {
      __privSetPendingPackageId(packagePrincipal || 0);
    }
    var fn;
    try {
      fn = new __privFunction(
        "require",
        "module",
        "exports",
        "__filename",
        "__dirname",
        "__exactDynamicImport",
        source);
    } finally {
      if (__privSetPendingPackageId) {
        // Clear (not pin 0): the compile's runBytecode already consumed the
        // pending id; this only matters if the compile threw first. Passing -1
        // clears the pending flag so a later eval/Function is treated as
        // unlabelled and inherits its caller. @ref LLP 0013#mechanism-2
        __privSetPendingPackageId(-1);
      }
    }
    // @ref LLP 0013#mechanism-2 — (Phase 3) — bind this package's compartment to
    // the fresh Domain the compile created, so its bare-global references
    // resolve natively through the compartment. No-op for root/builtins.
    if (__privSetCompartmentFor && compartment) {
      try { __privSetCompartmentFor(fn, compartment); } catch (e) {}
    }
    return fn;
  }
  const cache = Object.create(null);
  var mainModule = null;
  function getDebugModuleSourceLimit() {
    var configured = g.__exactDebugModuleSourceLimit;
    var limit = typeof configured === 'number' ? configured : Number(configured);
    if (!isFinite(limit) || limit <= 0) {
      return 256;
    }
    return Math.floor(limit);
  }
  function pushDebugModuleSource(entry) {
    g.__exactDebugModuleSources = g.__exactDebugModuleSources || [];
    if (!Array.isArray(g.__exactDebugModuleSources)) {
      return;
    }
    g.__exactDebugModuleSources.push(entry);
    var limit = getDebugModuleSourceLimit();
    if (g.__exactDebugModuleSources.length > limit) {
      g.__exactDebugModuleSources.splice(0, g.__exactDebugModuleSources.length - limit);
    }
  }
  function normalizeSpecifier(specifier) {
    if (typeof specifier !== 'string') {
      return String(specifier || '');
    }
    var out = specifier.replace(/\\/g, '/');
    if (out.indexOf('node:') === 0) {
      out = out.slice(5);
    }
    if (out.slice(-3) === '.js') {
      out = out.slice(0, -3);
    }
    return out;
  }
  function stripViteImportQuery(specifier) {
    if (typeof specifier !== 'string') {
      return specifier;
    }
    // Vite encodes JSON modules as `/path/file.json?import`. Native resolution
    // needs the underlying file path so the Rust resolver can classify the
    // module as JSON and read it from disk instead of treating the query string
    // as part of the filename.
    return specifier.replace(/\?import(?:&.*)?$/, '');
  }
  function isWindowsRuntime() {
    return (
      g.__exactPlatform === 'win32' ||
      (g.process && g.process.platform === 'win32')
    );
  }
  function formatTime(ms) {
    var t = typeof ms === 'number' ? ms : Number(ms);
    if (!isFinite(t) || t < 0) {
      return String(t) + 'ms';
    }
    if (t < 1000) {
      return t.toFixed(3).replace(/\.?0+$/, '') + 'ms';
    }
    if (t < 60000) {
      return (t / 1000).toFixed(3) + 's';
    }
    var totalSeconds = Math.floor(t / 1000);
    var hours = Math.floor(totalSeconds / 3600);
    var remainingSeconds = totalSeconds % 3600;
    var minutes = Math.floor(remainingSeconds / 60);
    var seconds = remainingSeconds % 60;
    var millis = Math.round(t) % 1000;
    var secondPart = String(seconds).padStart(2, '0') + '.' + String(millis).padStart(3, '0');
    if (hours > 0) {
      return hours + ':' + String(minutes).padStart(2, '0') + ':' + secondPart + ' (h:mm:ss.mmm)';
    }
    return minutes + ':' + secondPart + ' (m:ss.mmm)';
  }
  var _internalAsyncIdCounter = 0;
  var _internalAsyncHooksSymbols = {
    async_id_symbol: Symbol.for('nodejs.async_id_symbol')
  };
  function _internalOptionNames(flag) {
    var names = [flag];
    if (typeof flag === 'string') {
      if (flag.indexOf('_') !== -1) {
        names.push(flag.replace(/_/g, '-'));
      } else {
        names.push(flag.replace(/-/g, '_'));
      }
    }
    return names;
  }
  function _internalFindExecArgvOption(flag) {
    var execArgv = (typeof process === 'object' && process !== null && Array.isArray(process.execArgv))
      ? process.execArgv
      : (Array.isArray(globalThis.__exactExecArgv) ? globalThis.__exactExecArgv : []);
    var names = _internalOptionNames(flag);
    for (var i = 0; i < execArgv.length; i++) {
      var arg = String(execArgv[i]);
      for (var j = 0; j < names.length; j++) {
        var name = names[j];
        if (arg === name) return true;
        if (arg.indexOf(name + '=') === 0) return arg.slice(name.length + 1);
      }
    }
    return undefined;
  }
  function _internalGetOptionValue(flag) {
    var found = _internalFindExecArgvOption(flag);
    if (found !== undefined) {
      if (flag === '--max-http-header-size' || flag === '--test-concurrency') {
        var numeric = Number(found);
        return isFinite(numeric) ? numeric : undefined;
      }
      if (flag === '--inspect-port') {
        var inspectPort = found === true ? 9229 : Number(found);
        return { port: isFinite(inspectPort) ? inspectPort : 9229 };
      }
      return found;
    }
    if (flag === '--pending-deprecation') {
      var env = (typeof process === 'object' && process !== null && process.env) ? process.env : {};
      return !!(env && env.NODE_PENDING_DEPRECATION && String(env.NODE_PENDING_DEPRECATION).charAt(0) === '1');
    }
    if (flag === '--max-http-header-size') return 16384;
    return undefined;
  }
  function _patchBrokenSharedArrayBufferViews() {
    if (typeof SharedArrayBuffer !== 'function' || typeof Uint8Array !== 'function') {
      return;
    }
    var probeView;
    try {
      probeView = new Uint8Array(new SharedArrayBuffer(1));
      if (
        probeView.length !== 0 &&
        probeView.byteLength !== 0 &&
        Object.prototype.toString.call(probeView.buffer) === '[object SharedArrayBuffer]'
      ) {
        return;
      }
    } catch (_probeErr) {}

    function getSharedArrayBufferBacking(buffer) {
      if (!buffer || typeof buffer !== 'object') return null;
      if (Object.prototype.toString.call(buffer) !== '[object SharedArrayBuffer]') return null;
      if (!buffer._buffer || Object.prototype.toString.call(buffer._buffer) !== '[object ArrayBuffer]') {
        return null;
      }
      return buffer._buffer;
    }

    function exposeSharedArrayBufferView(view, originalBuffer) {
      if (!view || !originalBuffer) return view;
      try {
        Object.defineProperty(view, 'buffer', {
          configurable: true,
          enumerable: false,
          get: function() {
            return originalBuffer;
          }
        });
      } catch (_bufferErr) {}
      try {
        Object.defineProperty(view, '__exactSharedArrayBuffer', {
          value: originalBuffer,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_markerErr) {}
      return view;
    }

    function wrapCtor(name) {
      var NativeCtor = globalThis[name];
      if (typeof NativeCtor !== 'function' || NativeCtor.__exactSharedArrayBufferWrapped) {
        return;
      }

      function WrappedCtor(buffer, byteOffset, length) {
        if (!(this instanceof WrappedCtor)) {
          throw new TypeError('Constructor ' + name + ' requires "new"');
        }

        var backing = getSharedArrayBufferBacking(buffer);
        if (backing) {
          var view;
          if (arguments.length <= 1) {
            view = new NativeCtor(backing);
          } else if (arguments.length === 2) {
            view = new NativeCtor(backing, byteOffset);
          } else {
            view = new NativeCtor(backing, byteOffset, length);
          }
          return exposeSharedArrayBufferView(view, buffer);
        }

        if (arguments.length === 0) return new NativeCtor();
        if (arguments.length === 1) return new NativeCtor(buffer);
        if (arguments.length === 2) return new NativeCtor(buffer, byteOffset);
        return new NativeCtor(buffer, byteOffset, length);
      }

      var propNames = Object.getOwnPropertyNames(NativeCtor);
      for (var i = 0; i < propNames.length; i++) {
        var propName = propNames[i];
        if (propName === 'prototype' || propName === 'length' || propName === 'name') {
          continue;
        }
        try {
          Object.defineProperty(WrappedCtor, propName, Object.getOwnPropertyDescriptor(NativeCtor, propName));
        } catch (_copyErr) {}
      }
      WrappedCtor.prototype = NativeCtor.prototype;
      try {
        Object.defineProperty(WrappedCtor.prototype, 'constructor', {
          value: WrappedCtor,
          writable: true,
          configurable: true,
          enumerable: false
        });
      } catch (_ctorErr) {}
      try {
        Object.defineProperty(WrappedCtor, '__exactSharedArrayBufferWrapped', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_wrappedErr) {}
      globalThis[name] = WrappedCtor;
    }

    var ctorNames = [
      'Int8Array',
      'Uint8Array',
      'Uint8ClampedArray',
      'Int16Array',
      'Uint16Array',
      'Int32Array',
      'Uint32Array',
      'Float32Array',
      'Float64Array'
    ];
    if (typeof globalThis.Float16Array === 'function') ctorNames.push('Float16Array');
    if (typeof globalThis.BigInt64Array === 'function') ctorNames.push('BigInt64Array');
    if (typeof globalThis.BigUint64Array === 'function') ctorNames.push('BigUint64Array');
    for (var i = 0; i < ctorNames.length; i++) {
      wrapCtor(ctorNames[i]);
    }
    wrapCtor('DataView');
  }
  // Skip SharedArrayBuffer patching when the shared runtime bundle will
  // handle it.  The patch wraps 9+ TypedArray constructors eagerly —
  // expensive and rarely needed.
  if (!globalThis.__exactHasSharedRuntimeBundle) {
    _patchBrokenSharedArrayBufferViews();
  }

  function _patchBase64DomExceptions() {
    var nativeBtoa = typeof globalThis.btoa === 'function' ? globalThis.btoa : null;
    var nativeAtob = typeof globalThis.atob === 'function' ? globalThis.atob : null;

    function invalidCharacterError(message) {
      if (typeof globalThis.DOMException === 'function') {
        return new globalThis.DOMException(message, 'InvalidCharacterError');
      }
      var err = new Error(message);
      err.name = 'InvalidCharacterError';
      err.code = 5;
      return err;
    }

    if (nativeAtob && nativeAtob.__exactDomWrapped !== true) {
      var wrappedAtob = function(input) {
        try {
          return nativeAtob(String(input));
        } catch (_err) {
          throw invalidCharacterError('The string to be decoded is not correctly encoded.');
        }
      };
      try {
        Object.defineProperty(wrappedAtob, '__exactDomWrapped', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_atobMarkerErr) {}
      globalThis.atob = wrappedAtob;
    }

    if (nativeBtoa && nativeBtoa.__exactDomWrapped !== true) {
      var wrappedBtoa = function(input) {
        var str = String(input);
        for (var i = 0; i < str.length; i++) {
          if (str.charCodeAt(i) > 255) {
            throw invalidCharacterError('The string to be encoded contains characters outside of the Latin1 range.');
          }
        }
        try {
          return nativeBtoa(str);
        } catch (_err) {
          throw invalidCharacterError('The string to be encoded contains characters outside of the Latin1 range.');
        }
      };
      try {
        Object.defineProperty(wrappedBtoa, '__exactDomWrapped', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_btoaMarkerErr) {}
      globalThis.btoa = wrappedBtoa;
    }
  }
  _patchBase64DomExceptions();
  function _createNodeTestModule() {
    var context = null;
    var topLevelQueue = Promise.resolve();
    function _createMock(restoreList) {
      var restores = restoreList || [];
      return {
        method: function(target, propertyName) {
          if (typeof propertyName !== 'string') {
            throw new TypeError('The "propertyName" argument must be a string');
          }
          if (!target || (typeof target !== 'object' && typeof target !== 'function')) {
            throw new TypeError('Cannot mock property on non-object target');
          }
          if (typeof target[propertyName] !== 'function') {
            throw new TypeError('Cannot mock a non-function property');
          }

          var calls = [];
          var original = target[propertyName];
          var restored = false;

          var mocked = function() {
            var call = {
              thisArg: this,
              arguments: Array.prototype.slice.call(arguments),
              result: undefined,
              error: undefined
            };
            calls.push(call);
            try {
              call.result = original.apply(this, arguments);
              return call.result;
            } catch (e) {
              call.error = e;
              throw e;
            }
          };
          mocked.mock = { calls: calls };
          mocked.restore = function() {
            if (!restored) {
              target[propertyName] = original;
              restored = true;
            }
          };

          target[propertyName] = mocked;
          restores.push(function() {
            mocked.restore();
          });
          return mocked;
        }
      };
    }
    function _createTestContext() {
      var restoreList = [];
      var contextApi = {
        mock: _createMock(restoreList),
        __restoreMocks: function() {
          for (var i = 0; i < restoreList.length; i++) {
            try {
              restoreList[i]();
            } catch (_) {}
          }
          restoreList.length = 0;
        }
      };
      contextApi.test = function(name, fn) {
        if (typeof name === 'function' && fn === undefined) {
          fn = name;
        }
        if (typeof fn !== 'function') {
          return Promise.resolve();
        }
        var subContext = _createTestContext();
        var promise;
        if (fn.length >= 2) {
          promise = new Promise(function(resolve, reject) {
            var doneCalled = false;
            var done = function(error) {
              if (doneCalled) return;
              doneCalled = true;
              if (error) {
                reject(error);
              } else {
                resolve();
              }
            };
            try {
              fn(subContext, done);
            } catch (err) {
              if (!doneCalled) {
                reject(err);
              }
            }
          });
        } else {
          try {
            promise = Promise.resolve(fn(subContext));
          } catch (err) {
            promise = Promise.reject(err);
          }
        }
        return promise.finally(function() {
          if (typeof subContext.__restoreMocks === 'function') {
            subContext.__restoreMocks();
          }
        });
      };
      return contextApi;
    }
    function _runAfterQueue(afters) {
      var promise = Promise.resolve();
      for (var i = 0; i < afters.length; i++) {
        (function(hook) {
          promise = promise.then(function() {
            return hook();
          });
        })(afters[i]);
      }
      return promise;
    }
    function describe() {
      var fn = arguments[1];
      if (typeof fn !== 'function') {
        return Promise.resolve();
      }
      var localContext = { tests: [], afters: [], queue: Promise.resolve() };
      var previousContext = context;
      context = localContext;
      var result;
      try {
        result = fn();
      } catch (err) {
        context = previousContext;
        throw err;
      }
      context = previousContext;
      var done = Promise.resolve(result)
        .then(function() {
          return localContext.queue;
        })
        .then(function() {
          return _runAfterQueue(localContext.afters);
        });
      done.catch(function(err) { setTimeout(function() { throw err; }, 0); });
      return done;
    }
    function it() {
      var fn = arguments[1];
      if (typeof fn !== 'function') {
        return Promise.resolve();
      }
      var runTest = function() {
        var promise;
        var testContext = _createTestContext();
        if (fn.length >= 2) {
          promise = new Promise(function(resolve, reject) {
            var doneCalled = false;
            var done = function(error) {
              if (doneCalled) return;
              doneCalled = true;
              if (error) {
                reject(error);
              } else {
                resolve();
              }
            };
            try {
              fn(testContext, done);
            } catch (err) {
              if (!doneCalled) {
                reject(err);
              }
            }
          });
        } else {
          try {
            promise = Promise.resolve(fn(testContext));
          } catch (err) {
            promise = Promise.reject(err);
          }
        }
        return promise.finally(function() {
          if (typeof testContext.__restoreMocks === 'function') {
            testContext.__restoreMocks();
          }
        });
      };
      var promise;
      if (context) {
        promise = context.queue.then(runTest, runTest);
        context.queue = promise.catch(function() {});
        context.tests.push(promise);
      } else {
        promise = topLevelQueue.then(runTest, runTest);
        topLevelQueue = promise.catch(function() {});
      }
      return promise;
    }
    function test() {
      return it.apply(this, arguments);
    }
    function suite(name, fn) {
      return describe(name, fn);
    }
    function before() {}
    function beforeEach() {}
    function afterEach() {}
    function after(fn) {
      if (typeof fn !== 'function') return Promise.resolve();
      if (context) {
        context.afters.push(fn);
        return;
      }
      return Promise.resolve(fn());
    }
    // mock support for node:test
    var _mockRestoreList = [];
    var mock = {
      method: function(obj, methodName, impl) {
        var original = obj[methodName];
        var calls = [];
        var wrapper = function() {
          var result;
          var error;
          try {
            result = impl.apply(this, arguments);
          } catch (e) {
            error = e;
            throw e;
          } finally {
            calls.push({ arguments: Array.prototype.slice.call(arguments), result: result, error: error, this: this });
          }
          return result;
        };
        wrapper.mock = { calls: calls, callCount: function() { return calls.length; }, restore: function() { obj[methodName] = original; } };
        obj[methodName] = wrapper;
        _mockRestoreList.push(function() { obj[methodName] = original; });
        return wrapper;
      },
      fn: function(impl) {
        impl = impl || function() {};
        var calls = [];
        var wrapper = function() {
          var result = impl.apply(this, arguments);
          calls.push({ arguments: Array.prototype.slice.call(arguments), result: result });
          return result;
        };
        wrapper.mock = { calls: calls, callCount: function() { return calls.length; } };
        return wrapper;
      },
      restoreAll: function() {
        for (var i = 0; i < _mockRestoreList.length; i++) _mockRestoreList[i]();
        _mockRestoreList = [];
      }
    };
    var exported = function() {
      return test.apply(this, arguments);
    };
    exported.describe = describe;
    exported.it = it;
    exported.test = test;
    exported.suite = suite;
    exported.before = before;
    exported.beforeEach = beforeEach;
    exported.afterEach = afterEach;
    exported.after = after;
    exported.mock = mock;
    return exported;
  }
  // internal/linkedlist: circular doubly-linked list
  var _L = {
    init: function(item) { item._idleNext = item; item._idlePrev = item; },
    peek: function(item) { return item._idleNext === item ? null : item._idleNext; },
    remove: function(item) {
      if (item._idleNext) { item._idleNext._idlePrev = item._idlePrev; }
      if (item._idlePrev) { item._idlePrev._idleNext = item._idleNext; }
      item._idleNext = item; item._idlePrev = item;
    },
    append: function(list, item) {
      if (item._idleNext !== item) { _L.remove(item); }
      item._idleNext = list;
      item._idlePrev = list._idlePrev;
      list._idlePrev._idleNext = item;
      list._idlePrev = item;
    },
    isEmpty: function(item) { return item._idleNext === item; }
  };
  function _internalFsUtilsInvalidArgValue(name, value, reason) {
    var err = new TypeError('The "' + name + '" argument must be ' + reason + '. Received ' + value);
    err.code = 'ERR_INVALID_ARG_VALUE';
    return err;
  }
  function _internalFsUtilsRangeError(name, value, min, max) {
    var message = 'The value of "' + name + '" is out of range. It must be >= ' + min + ' && <= ' + max + '. Received ' + value;
    var err = new RangeError(message);
    err.code = 'ERR_OUT_OF_RANGE';
    return err;
  }
  function _internalFsUtilsStringToInt(value) {
    return parseInt(value, 10);
  }
  function _internalFsUtilsIsFd(fd) {
    return typeof fd === 'number' && Number.isInteger(fd) && fd >= 0;
  }
  function _internalFsUtilsIsFileMode(mode) {
    return typeof mode === 'number' && Number.isInteger(mode);
  }
  function _internalFsUtilsValidateFd(fd) {
    if (!_internalFsUtilsIsFd(fd)) {
      throw new TypeError('The "fd" argument must be a non-negative integer. Received ' + String(fd));
    }
  }
  function _internalFsUtilsToPathIfFileURL(value) {
    if (typeof value === 'string' || value instanceof String) {
      return value;
    }
    if (value && typeof value === 'object' && typeof value.path === 'string') {
      return value.path;
    }
    return value;
  }
  function _internalFsUtilsInvalidArgType(name, value, expected) {
    var err = new TypeError(
      'The "' + name + '" argument must be of type ' + expected + '. Received ' +
      (value === null ? 'null' : typeof value)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    return err;
  }
  function _internalFsUtilsValidateOffsetLength(offset, length, byteLength, mode, maxLength) {
    if (!Number.isInteger(offset) || offset < 0) {
      var offsetErr = new RangeError('The value of "offset" is out of range. It must be >= 0. Received ' + offset);
      offsetErr.code = 'ERR_OUT_OF_RANGE';
      throw offsetErr;
    }
    if (!Number.isInteger(length) || length < 0) {
      var lengthErr = new RangeError('The value of "length" is out of range. It must be >= 0. Received ' + length);
      lengthErr.code = 'ERR_OUT_OF_RANGE';
      throw lengthErr;
    }
    if (mode === 'write') {
      if (offset > byteLength) {
        var writeOffsetErr = new RangeError('The value of "offset" is out of range. It must be <= ' + byteLength + '. Received ' + offset);
        writeOffsetErr.code = 'ERR_OUT_OF_RANGE';
        throw writeOffsetErr;
      }
    }
    if (length > maxLength) {
      var maxLenErr = new RangeError('The value of "length" is out of range. It must be <= ' + maxLength + '. Received ' + length);
      maxLenErr.code = 'ERR_OUT_OF_RANGE';
      throw maxLenErr;
    }
    var max = byteLength - offset;
    if (length > max) {
      var lenErr = new RangeError('The value of "length" is out of range. It must be <= ' + max + '. Received ' + length);
      lenErr.code = 'ERR_OUT_OF_RANGE';
      throw lenErr;
    }
  }
  function _internalFsUtilsValidateOption(name, value, expectedType) {
    if (expectedType === 'boolean' && typeof value !== 'boolean') {
      var boolErr = new TypeError(
        'The "options.' + name + '" property must be of type boolean. Received type ' + typeof value + '.'
      );
      boolErr.code = 'ERR_INVALID_ARG_TYPE';
      throw boolErr;
    }
    if (expectedType === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) {
      var rangeError = new RangeError('The value of "options.' + name + '" is out of range. Received ' + value);
      rangeError.code = 'ERR_OUT_OF_RANGE';
      throw rangeError;
    }
  }
  function _internalFsUtilsValidateRmdirOptions(options) {
    if (options === undefined) {
      return { retryDelay: 100, maxRetries: 0, recursive: false };
    }
    if (options === null || typeof options !== 'object') {
      throw _internalFsUtilsInvalidArgType('options', options, 'object');
    }
    if (Object.prototype.hasOwnProperty.call(options, 'recursive')) {
      _internalFsUtilsValidateOption('recursive', options.recursive, 'boolean');
    }
    if (Object.prototype.hasOwnProperty.call(options, 'retryDelay')) {
      if (
        typeof options.retryDelay !== 'number' ||
        !Number.isFinite(options.retryDelay) ||
        options.retryDelay < 0
      ) {
        var retryErr = new RangeError(
          'The value of "options.retryDelay" is out of range. Received ' + options.retryDelay
        );
        retryErr.code = 'ERR_OUT_OF_RANGE';
        throw retryErr;
      }
    }
    if (Object.prototype.hasOwnProperty.call(options, 'maxRetries')) {
      if (
        typeof options.maxRetries !== 'number' ||
        !Number.isFinite(options.maxRetries) ||
        options.maxRetries < 0
      ) {
        var maxErr = new RangeError(
          'The value of "options.maxRetries" is out of range. Received ' + options.maxRetries
        );
        maxErr.code = 'ERR_OUT_OF_RANGE';
        throw maxErr;
      }
    }
    return {
      retryDelay: options.retryDelay === undefined ? 100 : options.retryDelay,
      maxRetries: options.maxRetries === undefined ? 0 : options.maxRetries,
      recursive: options.recursive === undefined ? false : options.recursive
    };
  }
  function _internalFsUtilsValidateRmOptionsSync(path, options) {
    var base = _internalFsUtilsValidateRmdirOptions(options);
    var hasForce = !!(options && Object.prototype.hasOwnProperty.call(options, 'force'));
    if (hasForce) {
      _internalFsUtilsValidateOption('force', options.force, 'boolean');
    }
    return {
      retryDelay: base.retryDelay,
      maxRetries: base.maxRetries,
      recursive: base.recursive,
      force: hasForce ? options.force : false
    };
  }
  function _internalFsUtilsSyncWriteStream() {}
  _internalFsUtilsSyncWriteStream.prototype = {
    _write: function(chunk, encoding, cb) {
      if (cb && typeof cb === 'function') {
        cb();
      }
    }
  };
  function _getExactNativeWrapState() {
    var root = typeof globalThis === 'object' ? globalThis : {};
    if (root.__exactNativeWrapState) {
      return root.__exactNativeWrapState;
    }

    var UV_EINVAL = -22;

    function unregisterFd(fd) {
      if (typeof fd !== 'number' || fd < 0) return;
      delete state.byFd[fd];
    }

    function registerHandle(handle) {
      if (!handle || typeof handle.fd !== 'number' || handle.fd < 0) return;
      state.byFd[handle.fd] = handle;
    }

    function BaseWrap(type, kind) {
      this._handleType = type;
      this._exactHandle = null;
      this._exactKind = kind || 'tcp';
      this._exactPath = null;
      this._refed = true;
      this.fd = -1;
      this.onread = null;
    }

    BaseWrap.prototype._setExactHandle = function(exactHandle, fd, kind, path) {
      unregisterFd(this.fd);
      this._exactHandle = exactHandle == null ? null : exactHandle;
      this._exactKind = kind || this._exactKind || 'tcp';
      this._exactPath = path || null;
      if (typeof fd === 'number' && fd >= 0) {
        this.fd = fd;
      } else if (typeof exactHandle === 'number' && exactHandle >= 0) {
        this.fd = exactHandle;
      } else if (this.fd == null) {
        this.fd = -1;
      }
      registerHandle(this);
      return this;
    };

    BaseWrap.prototype.close = function(callback) {
      unregisterFd(this.fd);
      if (this._exactHandle != null && typeof __exactTcpClose === 'function') {
        try { __exactTcpClose(this._exactHandle); } catch (_closeErr) {}
      }
      if (this._exactKind === 'pipe' && this._exactPath) {
        try { require('fs').unlinkSync(this._exactPath); } catch (_unlinkErr) {}
      }
      this._exactHandle = null;
      this._refed = false;
      this.fd = -1;
      if (typeof callback === 'function') {
        setTimeout(callback, 0);
      }
      return 0;
    };

    BaseWrap.prototype.ref = function() {
      this._refed = true;
      return this;
    };

    BaseWrap.prototype.unref = function() {
      this._refed = false;
      return this;
    };

    BaseWrap.prototype.hasRef = function() {
      return this._refed !== false;
    };

    BaseWrap.prototype.readStart = function() {
      return 0;
    };

    BaseWrap.prototype.readStop = function() {
      return 0;
    };

    function applyLocalName(target, info) {
      if (!target || !info) return;
      try {
        var parsed = JSON.parse(info);
        target.address = parsed.address;
        target.port = parsed.port;
        target.family = parsed.family;
      } catch (_parseErr) {}
    }

    function openRegisteredHandle(instance, fd, kind) {
      var existing = state.byFd[fd];
      if (existing && existing._exactHandle != null) {
        instance._setExactHandle(existing._exactHandle, fd, existing._exactKind || kind, existing._exactPath || null);
        return 0;
      }
      if (typeof __exactTcpFromFd !== 'function') {
        return UV_EINVAL;
      }
      try {
        var exactHandle = __exactTcpFromFd(fd);
        instance._setExactHandle(exactHandle, fd, kind, null);
        return 0;
      } catch (_openErr) {
        return UV_EINVAL;
      }
    }

    function TCP(type) {
      BaseWrap.call(this, type, 'tcp');
    }
    TCP.prototype = Object.create(BaseWrap.prototype);
    TCP.prototype.constructor = TCP;
    TCP.prototype.bind = function(address, port) {
      if (this._exactHandle != null) return UV_EINVAL;
      try {
        var exactHandle = __exactTcpListen(address, port, 128, 0, 0);
        this._setExactHandle(exactHandle, exactHandle, 'tcp', null);
        return 0;
      } catch (_bindErr) {
        return UV_EINVAL;
      }
    };
    TCP.prototype.bind6 = function(address, port) {
      if (this._exactHandle != null) return UV_EINVAL;
      try {
        var exactHandle = __exactTcpListen(address, port, 128, 1, 0);
        this._setExactHandle(exactHandle, exactHandle, 'tcp', null);
        return 0;
      } catch (_bindErr6) {
        return UV_EINVAL;
      }
    };
    TCP.prototype.open = function(fd) {
      return openRegisteredHandle(this, fd, 'tcp');
    };
    TCP.prototype.getsockname = function(out) {
      if (!out || this._exactHandle == null || typeof __exactTcpLocalAddr !== 'function') {
        return UV_EINVAL;
      }
      try {
        applyLocalName(out, __exactTcpLocalAddr(this._exactHandle));
        return 0;
      } catch (_socknameErr) {
        return UV_EINVAL;
      }
    };
    TCP.prototype.connect = function(req, address, port) {
      var self = this;
      try {
        var exactHandle = __exactTcpConnect(address, port);
        this._setExactHandle(exactHandle, exactHandle, 'tcp', null);
        setTimeout(function() {
          if (req && typeof req.oncomplete === 'function') {
            req.oncomplete(0, self, req, true, true);
          }
        }, 0);
        return 0;
      } catch (_connectErr) {
        return UV_EINVAL;
      }
    };
    TCP.prototype.shutdown = function(req) {
      var self = this;
      if (this._exactHandle == null || typeof __exactTcpShutdown !== 'function') {
        return UV_EINVAL;
      }
      try {
        __exactTcpShutdown(this._exactHandle, 1);
        setTimeout(function() {
          if (req && typeof req.oncomplete === 'function') {
            req.oncomplete(0, self, undefined);
          }
        }, 0);
        return 0;
      } catch (_shutdownErr) {
        return UV_EINVAL;
      }
    };
    TCP.prototype.setNoDelay = function(enable) {
      if (this._exactHandle == null || typeof __exactTcpSetNoDelay !== 'function') return 0;
      try { __exactTcpSetNoDelay(this._exactHandle, enable === false ? 0 : 1); } catch (_nodelayErr) {}
      return 0;
    };
    TCP.prototype.setKeepAlive = function(enable, delay) {
      if (this._exactHandle == null || typeof __exactTcpSetKeepAlive !== 'function') return 0;
      try {
        if (__exactTcpSetKeepAlive.length >= 3) {
          __exactTcpSetKeepAlive(this._exactHandle, enable === false ? 0 : 1, delay || 0);
        } else {
          __exactTcpSetKeepAlive(this._exactHandle, enable === false ? 0 : 1);
        }
      } catch (_keepAliveErr) {}
      return 0;
    };

    function Pipe(type) {
      BaseWrap.call(this, type, 'pipe');
    }
    Pipe.prototype = Object.create(BaseWrap.prototype);
    Pipe.prototype.constructor = Pipe;
    Pipe.prototype.bind = function(path) {
      if (this._exactHandle != null) return UV_EINVAL;
      try {
        var exactHandle = __exactUnixListen(path, 128);
        this._setExactHandle(exactHandle, exactHandle, 'pipe', path);
        return 0;
      } catch (_pipeBindErr) {
        return UV_EINVAL;
      }
    };
    Pipe.prototype.open = function(fd) {
      return openRegisteredHandle(this, fd, 'pipe');
    };

    function TCPConnectWrap() {}

    var state = {
      UV_EINVAL: UV_EINVAL,
      byFd: Object.create(null),
      TCP: TCP,
      Pipe: Pipe,
      TCPConnectWrap: TCPConnectWrap,
      tcpConstants: {
        SOCKET: 0
      },
      pipeConstants: {
        SOCKET: 0
      }
    };

    root.__exactNativeWrapState = state;
    return state;
  }
  var internalAnsiPattern = /[\u001B\u009B][[\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\d\/#&.:=?%@~_]+)*|[a-zA-Z\d]+(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?(?:\u0007|\u001B\u005C|\u009C))|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g;
  function internalStripVTControlCharacters(str) {
    return String(str).replace(internalAnsiPattern, '');
  }
  function internalIsZeroWidthCodePoint(code) {
    return code <= 0x1F ||
      (code >= 0x7F && code <= 0x9F) ||
      (code >= 0x300 && code <= 0x36F) ||
      (code >= 0x200B && code <= 0x200F) ||
      (code >= 0x20D0 && code <= 0x20FF) ||
      (code >= 0xFE00 && code <= 0xFE0F) ||
      (code >= 0xFE20 && code <= 0xFE2F) ||
      (code >= 0xE0100 && code <= 0xE01EF);
  }
  function internalIsFullWidthCodePoint(code) {
    return code >= 0x1100 && (
      code <= 0x115f ||
      code === 0x2329 ||
      code === 0x232a ||
      (code >= 0x2e80 && code <= 0x3247 && code !== 0x303f) ||
      (code >= 0x3250 && code <= 0x4dbf) ||
      (code >= 0x4e00 && code <= 0xa4c6) ||
      (code >= 0xa960 && code <= 0xa97c) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe10 && code <= 0xfe19) ||
      (code >= 0xfe30 && code <= 0xfe6b) ||
      (code >= 0xff01 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6) ||
      (code >= 0x1b000 && code <= 0x1b001) ||
      (code >= 0x1f200 && code <= 0x1f251) ||
      (code >= 0x1f300 && code <= 0x1f64f) ||
      (code >= 0x20000 && code <= 0x3fffd)
    );
  }
  function internalGetStringWidth(str, removeControlChars) {
    var text = String(str);
    var width = 0;
    var i = 0;
    if (removeControlChars !== false) {
      text = internalStripVTControlCharacters(text);
    }
    if (typeof text.normalize === 'function') {
      text = text.normalize('NFC');
    }
    while (i < text.length) {
      var code = text.codePointAt(i);
      if (internalIsFullWidthCodePoint(code)) {
        width += 2;
      } else if (!internalIsZeroWidthCodePoint(code)) {
        width += 1;
      }
      i += code > 0xFFFF ? 2 : 1;
    }
    return width;
  }
  function makeWindowsCryptoModule() {
    function toBytes(value, encoding) {
      if (value == null) return new Uint8Array(0);
      if (typeof value === 'string') {
        if (encoding === 'hex') {
          var hexLen = value.length - (value.length % 2);
          var hexOut = new Uint8Array(hexLen / 2);
          for (var hi = 0; hi < hexOut.length; hi++) {
            hexOut[hi] = parseInt(value.substr(hi * 2, 2), 16) || 0;
          }
          return hexOut;
        }
        return new TextEncoder().encode(value);
      }
      if (value instanceof ArrayBuffer) return new Uint8Array(value);
      if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      if (Array.isArray(value)) return new Uint8Array(value);
      return new TextEncoder().encode(String(value));
    }
    function concatChunks(chunks) {
      var total = 0;
      for (var i = 0; i < chunks.length; i++) total += chunks[i].length;
      var out = new Uint8Array(total);
      var offset = 0;
      for (var j = 0; j < chunks.length; j++) {
        out.set(chunks[j], offset);
        offset += chunks[j].length;
      }
      return out;
    }
    function bufferFromBytes(bytes) {
      if (typeof Buffer === 'function' && typeof Buffer.from === 'function') return Buffer.from(bytes);
      return bytes;
    }
    function hexToBytes(hex) {
      var clean = String(hex || '');
      var out = new Uint8Array(clean.length / 2);
      for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16) || 0;
      return out;
    }
    function encodeDigest(bytes, encoding) {
      if (!encoding || encoding === 'buffer') return bufferFromBytes(bytes);
      if (encoding === 'hex') {
        var hex = '';
        var digits = '0123456789abcdef';
        for (var i = 0; i < bytes.length; i++) hex += digits[(bytes[i] >> 4) & 15] + digits[bytes[i] & 15];
        return hex;
      }
      var buf = bufferFromBytes(bytes);
      if (buf && typeof buf.toString === 'function') return buf.toString(encoding);
      return String(bytes);
    }
    function randomBytes(size, callback) {
      var len = Number(size) || 0;
      if (len < 0) len = 0;
      var bytes = typeof __exactRandomBytes === 'function' ? __exactRandomBytes(len) : new Uint8Array(len);
      var out = bufferFromBytes(bytes);
      if (typeof callback === 'function') setTimeout(function() { callback(null, out); }, 0);
      return out;
    }
    function randomFillSync(buffer, offset, size) {
      var view = toBytes(buffer);
      var off = offset == null ? 0 : Number(offset) || 0;
      var len = size == null ? (view.length - off) : Number(size) || 0;
      var bytes = randomBytes(len);
      for (var i = 0; i < len; i++) view[off + i] = bytes[i] || 0;
      return buffer;
    }
    function randomUUID() {
      var b = randomBytes(16);
      b[6] = (b[6] & 15) | 64;
      b[8] = (b[8] & 63) | 128;
      return encodeDigest(b, 'hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
    }
    function Hash(algorithm) {
      if (!(this instanceof Hash)) return new Hash(algorithm);
      this._algorithm = String(algorithm || 'sha256').toLowerCase().replace(/-/g, '');
      this._chunks = [];
    }
    Hash.prototype.update = function(data, encoding) {
      this._chunks.push(toBytes(data, encoding));
      return this;
    };
    Hash.prototype.digest = function(encoding) {
      var data = concatChunks(this._chunks);
      if (typeof __exactHashRaw === 'function') return encodeDigest(__exactHashRaw(this._algorithm, data), encoding);
      if (typeof __exactHashSync === 'function') return encodeDigest(hexToBytes(__exactHashSync(this._algorithm, data)), encoding || 'hex');
      throw new Error('crypto hashing is unavailable');
    };
    Hash.prototype.copy = function() {
      var copy = new Hash(this._algorithm);
      copy._chunks = this._chunks.slice();
      return copy;
    };
    function Hmac(algorithm, key) {
      if (!(this instanceof Hmac)) return new Hmac(algorithm, key);
      this._algorithm = String(algorithm || 'sha256').toLowerCase().replace(/-/g, '');
      this._key = toBytes(key);
      this._chunks = [];
    }
    Hmac.prototype.update = function(data, encoding) {
      this._chunks.push(toBytes(data, encoding));
      return this;
    };
    Hmac.prototype.digest = function(encoding) {
      if (typeof __exactHmacSync !== 'function') throw new Error('crypto HMAC is unavailable');
      return encodeDigest(hexToBytes(__exactHmacSync(this._algorithm, this._key, concatChunks(this._chunks))), encoding || 'hex');
    };
    var mod = {
      createHash: function(algorithm) { return new Hash(algorithm); },
      Hash: Hash,
      createHmac: function(algorithm, key) { return new Hmac(algorithm, key); },
      Hmac: Hmac,
      hash: function(algorithm, data, outputEncoding) {
        return new Hash(algorithm).update(data).digest(outputEncoding || 'hex');
      },
      randomBytes: randomBytes,
      randomFillSync: randomFillSync,
      randomFill: function(buffer, offset, size, callback) {
        if (typeof offset === 'function') { callback = offset; offset = 0; size = undefined; }
        if (typeof size === 'function') { callback = size; size = undefined; }
        try {
          var result = randomFillSync(buffer, offset, size);
          setTimeout(function() { callback(null, result); }, 0);
        } catch (err) {
          setTimeout(function() { callback(err); }, 0);
        }
      },
      randomUUID: randomUUID,
      getRandomValues: function(arr) { return globalThis.crypto.getRandomValues(arr); },
      webcrypto: globalThis.crypto,
      subtle: globalThis.crypto && globalThis.crypto.subtle,
      getHashes: function() { return ['sha1', 'sha256', 'sha384', 'sha512']; },
      timingSafeEqual: function(a, b) {
        var av = toBytes(a);
        var bv = toBytes(b);
        if (av.length !== bv.length) throw new RangeError('Input buffers must have the same byte length');
        var diff = 0;
        for (var i = 0; i < av.length; i++) diff |= av[i] ^ bv[i];
        return diff === 0;
      }
    };
    mod.default = mod;
    return mod;
  }
  var internalModules = {
    'internal/util/debuglog': {
      formatTime: formatTime,
      debuglog: function() { return function() {}; }
    },
    'internal/linkedlist': _L,
    'internal/util': {
      sleep: function(ms) {
        var end = Date.now() + ms;
        while (Date.now() < end) { /* busy-wait */ }
      }
    },
    'internal/util/inspect': {
      inspect: function(value, options) {
        return require('util').inspect(value, options);
      },
      getStringWidth: internalGetStringWidth,
      stripVTControlCharacters: internalStripVTControlCharacters,
      isZeroWidthCodePoint: internalIsZeroWidthCodePoint
    },
    'internal/options': {
      getOptionValue: _internalGetOptionValue,
      generateConfigJsonSchema: function() { return {}; }
    },
    'internal/http': {
      kOutHeaders: Symbol.for('nodejs.http.outHeadersKey')
    },
    'internal/net': {
      isLoopback: function(address) {
        if (typeof address !== 'string') return false;
        if (address === 'localhost') return true;
        if (address === '127.0.0.1' || address === '127.0.0.255') return true;
        if (address.indexOf('127.') === 0) return true;
        return address === '[::1]' || address === '[0:0:0:0:0:0:0:1]';
      },
      kReinitializeHandle: Symbol.for('nodejs.net.kReinitializeHandle'),
      normalizedArgsSymbol: Symbol.for('nodejs.net.normalizedArgs')
    },
    'internal/async_hooks': {
      newAsyncId: function() {
        _internalAsyncIdCounter += 1;
        return _internalAsyncIdCounter;
      },
      symbols: _internalAsyncHooksSymbols
    },
    'internal/timers': {
      kTimeout: Symbol.for('kTimeout'),
      enroll: function() {},
      unenroll: function() {},
      active: function() {},
      setUnrefTimeout: function(callback, after) {
        if (typeof callback !== 'function') {
          var err = new TypeError('The "callback" argument must be of type function. Received ' + typeof callback);
          err.code = 'ERR_INVALID_ARG_TYPE';
          throw err;
        }
        var timer = setTimeout(callback, after);
        timer.unref();
        return timer;
      }
    },
    'internal/assert/myers_diff': {
      myersDiff: function(arr1, arr2) {
        var max = arr1.length + arr2.length;
        if (max >= 0x80000000) {
          var err = new RangeError(
            'The value of "myersDiff input size" is out of range. It must be < 2^31. Received ' + max
          );
          err.code = 'ERR_OUT_OF_RANGE';
          throw err;
        }
        return [];
      }
    },
    'internal/crypto/util': {
      getOpenSSLSecLevel: function() { return 0; }
    },
    'internal/crypto/x509': {
      isX509Certificate: function(value) {
        return !!(value && value.constructor && value.constructor.name === 'X509Certificate');
      }
    },
    'internal/url': {
      isURL: function(value) {
        if (typeof globalThis.URL === 'function' && value instanceof globalThis.URL) {
          return true;
        }
        if (!value || (typeof value !== 'object' && typeof value !== 'function')) {
          return false;
        }
        return !!(
          value.constructor &&
          value.constructor.name === 'URL' &&
          typeof value.href === 'string'
        );
      }
    },
    'internal/fs/utils': {
      isFd: _internalFsUtilsIsFd,
      isFileMode: _internalFsUtilsIsFileMode,
      validateFd: _internalFsUtilsValidateFd,
      toPathIfFileURL: _internalFsUtilsToPathIfFileURL,
      validateOffsetLengthRead: function(offset, length, byteLength, lengthIsBigInt) {
        if (lengthIsBigInt !== undefined && lengthIsBigInt) {
          if (typeof offset === 'bigint' || typeof length === 'bigint') {
            offset = _internalFsUtilsStringToInt(offset);
            length = _internalFsUtilsStringToInt(length);
          }
        }
        _internalFsUtilsValidateOffsetLength(offset, length, byteLength, 'read', (2 ** 31) - 1);
      },
      validateOffsetLengthWrite: function(offset, length, byteLength, lengthIsBigInt) {
        if (lengthIsBigInt !== undefined && lengthIsBigInt) {
          if (typeof offset === 'bigint' || typeof length === 'bigint') {
            offset = _internalFsUtilsStringToInt(offset);
            length = _internalFsUtilsStringToInt(length);
          }
        }
        _internalFsUtilsValidateOffsetLength(offset, length, byteLength, 'write', (2 ** 31) - 1);
      },
      stringToFlags: function(flag) {
        var constants = require('fs').constants || {};
        if (typeof flag !== 'string' || flag === '') {
          var err = new TypeError('The flags argument must be a valid flags string. Received ' + flag);
          err.code = 'ERR_INVALID_ARG_VALUE';
          throw err;
        }
        var hasPlus = flag.indexOf('+') !== -1;
        if (flag.indexOf('+') !== flag.lastIndexOf('+')) {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        if (hasPlus && flag.indexOf('+') !== flag.length - 1) {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        var flagChars = hasPlus ? flag.slice(0, -1) : flag;
        var hasSync = false;
        var hasExclusive = false;
        var modeFlags = '';
        for (var i = 0; i < flagChars.length; i++) {
          var ch = flagChars.charAt(i);
          if (ch === 's') {
            if (hasSync) throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
            hasSync = true;
          } else if (ch === 'x') {
            if (hasExclusive) throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
            hasExclusive = true;
          } else if (ch === 'r' || ch === 'w' || ch === 'a') {
            if (modeFlags.length >= 1) throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
            modeFlags = ch;
          } else {
            throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
          }
        }
        if (modeFlags.length !== 1) {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        if (hasExclusive && modeFlags === 'r') {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        var oSync = constants.O_SYNC || 0;
        var result = 0;
        if (modeFlags === 'r') {
          result = hasPlus ? constants.O_RDWR || 2 : constants.O_RDONLY || 0;
        } else if (modeFlags === 'w') {
          result = (constants.O_WRONLY || 1) | (constants.O_CREAT || 64) | (constants.O_TRUNC || 512);
        } else {
          result = (constants.O_APPEND || 1024) | (constants.O_CREAT || 64) | (constants.O_WRONLY || 1);
        }
        if (hasPlus) {
          result = (result & ~(constants.O_WRONLY || 1)) | (constants.O_RDWR || 2);
        }
        if (hasExclusive) {
          result |= constants.O_EXCL || 128;
        }
        if (hasSync) {
          result |= oSync;
        }
        return result;
      },
      validateRmdirOptions: _internalFsUtilsValidateRmdirOptions,
      validateRmOptionsSync: _internalFsUtilsValidateRmOptionsSync,
      BigIntStats: function(
        dev,
        mode,
        nlink,
        uid,
        gid,
        rdev,
        blksize,
        ino,
        size,
        blocks,
        atimeMs,
        mtimeMs,
        ctimeMs,
        birthtimeMs,
        atimeNs,
        mtimeNs,
        ctimeNs,
        birthtimeNs
      ) {
        function coerceBigInt(value) {
          if (typeof value === 'bigint') return value;
          return BigInt(typeof value === 'number' ? value : 0);
        }
        function coerceNumber(value) {
          if (typeof value === 'bigint') return Number(value);
          return typeof value === 'number' ? value : 0;
        }
        // @ref LLP 0005#bytecode-precompilation-hermesc — Hermes 0.11 parses
        // BigInt(...) calls but rejects BigInt literal syntax during bootstrap
        // HBC generation.
        var S_IFMT = BigInt(0xF000);
        var S_IFREG = BigInt(0x8000);
        var S_IFDIR = BigInt(0x4000);
        var S_IFLNK = BigInt(0xA000);
        var S_IFBLK = BigInt(0x6000);
        var S_IFCHR = BigInt(0x2000);
        var S_IFIFO = BigInt(0x1000);
        var S_IFSOCK = BigInt(0xC000);
        var modeBigint = coerceBigInt(mode);
        var modeType = modeBigint & S_IFMT;
        this.dev = coerceBigInt(dev);
        this.ino = coerceBigInt(ino);
        this.mode = coerceBigInt(mode);
        this.nlink = coerceBigInt(nlink);
        this.uid = coerceBigInt(uid);
        this.gid = coerceBigInt(gid);
        this.rdev = coerceBigInt(rdev);
        this.size = coerceBigInt(size);
        this.blksize = coerceBigInt(blksize);
        this.blocks = coerceBigInt(blocks);
        this.atimeMs = coerceBigInt(atimeMs);
        this.mtimeMs = coerceBigInt(mtimeMs);
        this.ctimeMs = coerceBigInt(ctimeMs);
        this.birthtimeMs = coerceBigInt(birthtimeMs);
        this.atimeNs = coerceBigInt(atimeNs);
        this.mtimeNs = coerceBigInt(mtimeNs);
        this.ctimeNs = coerceBigInt(ctimeNs);
        this.birthtimeNs = coerceBigInt(birthtimeNs);
        this.atime = new Date(coerceNumber(this.atimeMs));
        this.mtime = new Date(coerceNumber(this.mtimeMs));
        this.ctime = new Date(coerceNumber(this.ctimeMs));
        this.birthtime = new Date(coerceNumber(this.birthtimeMs));
        this._isFile = modeType === S_IFREG;
        this._isDir = modeType === S_IFDIR;
        this._isSymlink = modeType === S_IFLNK;
        this._isBlkDev = modeType === S_IFBLK;
        this._isChrDev = modeType === S_IFCHR;
        this._isFifo = modeType === S_IFIFO;
        this._isSock = modeType === S_IFSOCK;
      },
      getDirents: function(path, entries, callback) {
        if (callback === undefined || callback === null) {
          callback = null;
        }
        if (callback !== null && typeof callback !== 'function') {
          var callbackErr = new TypeError(
            'The "callback" argument must be of type function. Received ' + typeof callback
          );
          callbackErr.code = 'ERR_INVALID_ARG_TYPE';
          throw callbackErr;
        }
        var pair = entries || [];
        var names = Array.isArray(pair[0]) ? pair[0] : [];
        var types = Array.isArray(pair[1]) ? pair[1] : [];
        if (typeof path !== 'string' && !Buffer.isBuffer(path)) {
          var err = new TypeError('The "path" argument must be of type string or an ' +
            'instance of Buffer. Received type ' + (path === null ? 'null' : typeof path) +
            ' (' + path + ')');
          if (callback) return callback(err);
          throw err;
        }
        var fs = require('fs');
        var direntTypeUnknown = 0;
        var direntTypeFile = 1;
        var direntTypeDir = 2;
        var direntTypeLink = 3;
        var direntTypeFifo = 4;
        var direntTypeSocket = 5;
        var direntTypeChar = 6;
        var direntTypeBlock = 7;
        function statFromType(parentPath, entryName, type) {
          if (type === direntTypeFile) {
            return {
              isFile: function() { return true; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeDir) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return true; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeLink) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return true; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeFifo) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return true; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeSocket) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return true; },
            };
          }
          if (type === direntTypeChar) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return true; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeBlock) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return true; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          var fullPath = String(path);
          if (typeof entryName === 'string') {
            fullPath += '/' + entryName;
          } else {
            fullPath += '/' + String(entryName);
          }
          try {
            return fs.lstatSync(fullPath);
          } catch (_ignored) {
            return null;
          }
        }
        var out = [];
        for (var i = 0; i < names.length; i++) {
          out.push(new (require('fs').Dirent)(
            names[i],
            path,
            statFromType(path, names[i], types[i])
          ));
        }
        if (callback) {
          return callback(null, out);
        }
        return out;
      },
      getDirent: function(path, name, type, callback) {
        if (callback !== undefined && typeof callback !== 'function') {
          var callbackErr = new TypeError(
            'The "callback" argument must be of type function. Received ' + typeof callback
          );
          callbackErr.code = 'ERR_INVALID_ARG_TYPE';
          throw callbackErr;
        }
        if (typeof path !== 'string' && !Buffer.isBuffer(path)) {
          var err = new TypeError('The "path" argument must be of type string or an ' +
            'instance of Buffer. Received type ' + (path === null ? 'null' : typeof path) +
            ' (' + path + ')');
          if (callback) return callback(err);
          throw err;
        }
        if (typeof name !== 'string' && !Buffer.isBuffer(name)) {
          var nameErr = new TypeError('The "name" argument must be of type string or an ' +
            'instance of Buffer. Received type ' + (name === null ? 'null' : typeof name) +
            ' (' + name + ')');
          if (callback) return callback(nameErr);
          throw nameErr;
        }
        var fs = require('fs');
        var constants = internalModules['internal/test/binding'].internalBinding.call(
          internalModules['internal/test/binding'],
          'constants'
        ).fs;
        var unknown = constants && constants.UV_DIRENT_UNKNOWN;
        var stat = null;
        if (type === unknown) {
          try {
            stat = fs.lstatSync(String(path) + '/' + name);
          } catch (_ignored) {}
        } else {
          stat = {
            isFile: function() { return type === constants.UV_DIRENT_FILE; },
            isDirectory: function() { return type === constants.UV_DIRENT_DIR; },
            isSymbolicLink: function() { return type === constants.UV_DIRENT_LINK; },
            isBlockDevice: function() { return type === constants.UV_DIRENT_BLOCK; },
            isCharacterDevice: function() { return type === constants.UV_DIRENT_CHAR; },
            isFIFO: function() { return type === constants.UV_DIRENT_FIFO; },
            isSocket: function() { return type === constants.UV_DIRENT_SOCKET; },
          };
        }
        var result = new (require('fs').Dirent)(name, path, stat);
        if (callback) return callback(null, result);
        return result;
      },
      SyncWriteStream: _internalFsUtilsSyncWriteStream,
      kMinPoolSpace: 8192
    },
    'internal/test/binding': {
      internalBinding: function(name) {
      if (name === 'tty_wrap') {
        var streamBasePrototype = {};
        var defineStreamBaseAccessor = function(propertyName, slotName) {
          Object.defineProperty(streamBasePrototype, propertyName, {
            configurable: true,
            enumerable: false,
            get: function() {
              if (!this || !Object.prototype.hasOwnProperty.call(this, slotName)) {
                throw new TypeError('Cannot read ' + propertyName + ' on incompatible receiver');
              }
              return this[slotName];
            },
            set: function(value) {
              if (!this || !Object.prototype.hasOwnProperty.call(this, slotName)) {
                throw new TypeError('Cannot set ' + propertyName + ' on incompatible receiver');
              }
              this[slotName] = value;
            }
          });
        };
        defineStreamBaseAccessor('bytesRead', '__exactTtyBytesRead');
        defineStreamBaseAccessor('fd', '__exactTtyFd');
        defineStreamBaseAccessor('_externalStream', '__exactTtyExternalStream');
        function TTY(fd) {
          if (!(this instanceof TTY)) return new TTY(fd);
          Object.defineProperty(this, '__exactTtyBytesRead', {
            value: 0,
            writable: true,
            configurable: true
          });
          Object.defineProperty(this, '__exactTtyFd', {
            value: typeof fd === 'number' ? fd : -1,
            writable: true,
            configurable: true
          });
          Object.defineProperty(this, '__exactTtyExternalStream', {
            value: null,
            writable: true,
            configurable: true
          });
        }
        TTY.prototype = Object.create(streamBasePrototype);
        TTY.prototype.constructor = TTY;
        return { TTY: TTY };
      }
      if (name === 'crypto') {
        return {
          testFipsCrypto: function() {
            return 0;
          }
        };
      }
      if (name === 'fs') {
        return {
          FSReqCallback: function() {},
          fstat: function() {
            return [0, 0, 0, 0, 0, 0, 0, 0, 0];
          },
          readdir: function(path, encoding, types, req, ctx) {
            var entries = [];
            var entryTypes = [];
            var name = typeof _pathToString === 'function' ? _pathToString(path) : String(path);
            var dirs = require('fs').readdirSync(name);
            for (var i = 0; i < dirs.length; i++) {
              entries.push(dirs[i]);
              entryTypes.push(types ? 1 : 0);
            }
            if (req && typeof req.oncomplete === 'function') {
              req.oncomplete(null, [entries, entryTypes]);
              return;
            }
            return [entries, entryTypes];
          },
          writeFileUtf8: function(path, data) {
            var buffer = (typeof data === 'string') ? Buffer.from(data, 'utf8') : Buffer.from(data);
            return require('fs').writeFileSync(String(path), buffer);
          },
          openFileHandle: function(path, flags, mode, cb, ctx) {
            var handle = {
              fd: -1,
              close: function() {
                var closePath = this.path;
                if (typeof this.fd === 'number' && this.fd >= 0) {
                  require('fs').closeSync(this.fd);
                  this.fd = -1;
                }
              }
            };
            try {
              handle.fd = require('fs').openSync(String(path), flags, mode);
              if (ctx && typeof ctx === 'object') {
                ctx.errno = undefined;
              }
              handle.path = String(path);
            } catch (err) {
              if (ctx && typeof ctx === 'object') {
                ctx.errno = err && err.errno;
              }
              throw err;
            }
            return handle;
          },
        };
      }
      if (name === 'uv') {
        if (typeof globalThis === 'object' && globalThis.__exactUvEOFValue === undefined) {
          globalThis.__exactUvEOFValue = -4095;
        }
        return {
          UV_EACCES: -13,
            UV_EBADF: -9,
            UV_EBUSY: -16,
            UV_EINVAL: _getExactNativeWrapState().UV_EINVAL,
            UV_EEXIST: -17,
            UV_EOF: -4095,
            UV_EIO: -5,
            UV_EISDIR: -21,
            UV_ELOOP: -40,
            UV_EMFILE: -24,
            UV_ENAMETOOLONG: -63,
            UV_ENOENT: -2,
            UV_ENOMEM: -12,
            UV_ENETUNREACH: -101,
            UV_ENOSPC: -28,
            UV_ENOSYS: -78,
            UV_ENOTDIR: -20,
            UV_ENOTEMPTY: -66,
            UV_EPERM: -1,
            UV_ERANGE: -34,
            UV_EROFS: -30,
            UV_ESPIPE: -29,
            UV_EXDEV: -18,
            UV_ETXTBSY: -26,
            UV_UNKNOWN: -4094,
          };
        }
        if (name === 'constants') {
          return {
            fs: {
              UV_FS_SYMLINK_DIR: 1,
              UV_FS_SYMLINK_JUNCTION: 2,
              UV_DIRENT_UNKNOWN: 0,
              UV_DIRENT_FILE: 1,
              UV_DIRENT_DIR: 2,
              UV_DIRENT_LINK: 3,
              UV_DIRENT_FIFO: 4,
              UV_DIRENT_SOCKET: 5,
              UV_DIRENT_CHAR: 6,
              UV_DIRENT_BLOCK: 7,
              UV_FS_O_FILEMAP: 0,
              UV_FS_COPYFILE_EXCL: 1,
              UV_FS_COPYFILE_FICLONE: 2,
              UV_FS_COPYFILE_FICLONE_FORCE: 4,
            },
          };
        }
        if (name === 'timers') {
          return {
            getLibuvNow: function() { return typeof performance !== 'undefined' && typeof performance.now === 'function' ? (Math.floor(performance.now()) | 0) : 0; },
            scheduleTimer: function() {},
            toggleTimerRef: function() {},
            toggleImmediateRef: function() {}
          };
        }
        if (name === 'stream_wrap') {
          if (typeof globalThis === 'object') {
            if (!globalThis.__exactStreamWrapState) {
              globalThis.__exactStreamWrapState = [];
            }
            if (globalThis.__exactStreamWrapReadBytesOrErrorIndex === undefined) {
              globalThis.__exactStreamWrapReadBytesOrErrorIndex = 0;
            }
          }
          return {
            streamBaseState: typeof globalThis === 'object' ? globalThis.__exactStreamWrapState : [],
            kReadBytesOrError: typeof globalThis === 'object' ? globalThis.__exactStreamWrapReadBytesOrErrorIndex : 0,
            ShutdownWrap: function() {}
          };
        }
        if (name === 'tcp_wrap') {
          var tcpWrapState = _getExactNativeWrapState();
          return {
            TCP: tcpWrapState.TCP,
            TCPConnectWrap: tcpWrapState.TCPConnectWrap,
            constants: tcpWrapState.tcpConstants
          };
        }
        if (name === 'pipe_wrap') {
          var pipeWrapState = _getExactNativeWrapState();
          return {
            Pipe: pipeWrapState.Pipe,
            constants: pipeWrapState.pipeConstants
          };
        }
        if (name === 'test' && this && this.test) {
          return this.test;
        }
        return {};
      }
    },
    'internal/child_process': (function() {
      var kChannelHandle = globalThis.__exactKChannelHandleKey;
      if (kChannelHandle === undefined) {
        kChannelHandle = '__exactKChannelHandle';
        globalThis.__exactKChannelHandleKey = kChannelHandle;
      }
      function getValidStdio(stdio, sync) {
        if (typeof stdio === 'string') {
          if (stdio !== 'ignore' && stdio !== 'pipe' && stdio !== 'inherit' && stdio !== 'overlapped') {
            var err1 = new TypeError('The value "' + stdio + '" is invalid for option "stdio"');
            err1.code = 'ERR_INVALID_ARG_VALUE';
            throw err1;
          }
          stdio = [stdio, stdio, stdio];
        } else if (!Array.isArray(stdio)) {
          var err2 = new TypeError('The value "' + String(stdio) + '" is invalid for option "stdio"');
          err2.code = 'ERR_INVALID_ARG_VALUE';
          throw err2;
        }
        while (stdio.length < 3) stdio.push(undefined);
        var result = { stdio: [], ipc: undefined, ipcFd: undefined };
        for (var i = 0; i < stdio.length; i++) {
          var s = stdio[i];
          if (s === 'ignore' || s === undefined || s === null) {
            result.stdio.push({ type: 'ignore' });
          } else if (s === 'pipe' || s === 'overlapped') {
            result.stdio.push({ type: 'pipe' });
          } else if (s === 'inherit') {
            result.stdio.push({ type: 'fd', fd: i });
          } else if (s === 'ipc') {
            if (sync) {
              var err3 = new Error('IPC is not supported with synchronous forks');
              err3.code = 'ERR_IPC_SYNC_FORK';
              throw err3;
            }
            if (result.ipc !== undefined) {
              var err4 = new Error('Only one IPC pipe is allowed');
              err4.code = 'ERR_IPC_ONE_PIPE';
              throw err4;
            }
            result.ipc = { type: 'ipc' };
            result.ipcFd = i;
            result.stdio.push({ type: 'ipc' });
          } else if (typeof s === 'number') {
            result.stdio.push({ type: 'fd', fd: s });
          } else if (s && typeof s === 'object') {
            if (typeof s.fd === 'number') {
              result.stdio.push({ type: 'fd', fd: s.fd });
            } else if (s._handle || s.handle || s._writableState || s._readableState) {
              result.stdio.push({ type: 'fd', fd: i });
            } else {
              var err5 = new TypeError('The value "' + String(s) + '" is invalid for option "stdio"');
              err5.code = 'ERR_INVALID_ARG_VALUE';
              throw err5;
            }
          } else {
            var err6 = new TypeError('The value "' + String(s) + '" is invalid for option "stdio"');
            err6.code = 'ERR_INVALID_SYNC_FORK_INPUT';
            throw err6;
          }
        }
        return result;
      }
      return {
        getValidStdio: getValidStdio,
        kChannelHandle: kChannelHandle,
        ChildProcess: null  // Will be set after child_process is loaded
      };
    })(),
    'bun:internal-for-testing': {
      fsStreamInternals: {},
      memfd_create: function() { return -1; },
      setSyntheticAllocationLimitForTesting: function() {},
      setSocketOptions: function() {},
      canonicalizeIP: function(ip) { return ip; },
      nativeFrameForTesting: function() {},
      getEventLoopStats: function() {
        return { min: 0, max: 0, avg: 0, count: 0 };
      },
      timerInternals: {
        timerClockMs: function() { return Date.now(); },
      },
      structuredCloneAdvanced: function(value) {
        return JSON.parse(JSON.stringify(value));
      },
    }
  };
  if (isWindowsRuntime()) {
    internalModules.crypto = makeWindowsCryptoModule();
  }
  var streamBuiltinsCache = null;
  var streamInternalModuleCache = null;
  var eventTargetModuleCache = null;

  function _resolveAbortError(name) {
    var err = new Error(name + ' is missing');
    err.code = 'ERR_STREAM_PREMATURE_CLOSE';
    return err;
  }

  function _addAbortSignalCompat(signal, stream) {
    if (!stream || typeof stream.destroy !== 'function') {
      return stream;
    }
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', function() {
        var abortErr = new Error('The operation was aborted');
        abortErr.code = 'ABORT_ERR';
        abortErr.name = 'AbortError';
        stream.destroy(abortErr);
      });
    }
    return stream;
  }

  function _getStreamBuiltins() {
    if (!streamBuiltinsCache) {
      try {
        streamBuiltinsCache = load('stream');
      } catch (err) {
        streamBuiltinsCache = {};
      }
    }
    return streamBuiltinsCache;
  }

  function _loadNamedStreamInternal(name) {
    if (!streamInternalModuleCache) {
      streamInternalModuleCache = Object.create(null);
    }
    if (Object.prototype.hasOwnProperty.call(streamInternalModuleCache, name)) {
      return streamInternalModuleCache[name];
    }
    var stream = _getStreamBuiltins();
    var result = null;

    if (name === 'internal/streams/add-abort-signal') {
      var streamAddAbortSignal = stream.addAbortSignal || _addAbortSignalCompat;
      var streamAddAbortSignalNoValidate =
        stream.addAbortSignalNoValidate || _addAbortSignalCompat;
      result = {
        addAbortSignal: streamAddAbortSignal,
        addAbortSignalNoValidate: streamAddAbortSignalNoValidate
      };
    } else if (name === 'internal/streams/compose') {
      result = stream.compose || function() {
        throw _resolveAbortError('compose');
      };
    } else if (name === 'internal/streams/state') {
      result = {
        getDefaultHighWaterMark: stream.getDefaultHighWaterMark || function(_objectMode) { return _objectMode ? 16 : 16384; },
        setDefaultHighWaterMark: stream.setDefaultHighWaterMark || function() {}
      };
    } else if (name === 'internal/streams/destroy') {
      result = {
        destroy: function(streamInstance, err) {
          if (streamInstance && typeof streamInstance.destroy === 'function') {
            streamInstance.destroy(err);
          }
          return streamInstance;
        },
        undestroy: function(streamInstance) {
          if (streamInstance && typeof streamInstance._undestroy === 'function') {
            streamInstance._undestroy();
          }
        },
        errorOrDestroy: function(streamInstance, err) {
          if (err && streamInstance && typeof streamInstance.destroy === 'function') {
            streamInstance.destroy(err);
          }
          return streamInstance;
        },
        destroyer: function(streamInstance, err) {
          if (streamInstance && typeof streamInstance.destroy === 'function') {
            streamInstance.destroy(err);
          }
          return streamInstance;
        }
      };
    } else if (name === 'internal/streams/duplex') {
      result = stream.Duplex;
    } else if (name === 'internal/streams/end-of-stream') {
      result = stream.finished || function() {};
    } else if (name === 'internal/streams/from') {
      var streamFrom = stream.Readable && stream.Readable.from ? stream.Readable.from : function() {};
      streamFrom.from = streamFrom;
      streamFrom.default = streamFrom;
      result = streamFrom;
    } else if (name === 'internal/streams/legacy') {
      result = stream;
    } else if (name === 'internal/streams/operators') {
      if (stream && stream.Readable && stream.Readable.prototype) {
        result = {
          map: function(source, fn, options) { return stream.Readable.prototype.map.call(source, fn, options); },
          filter: function(source, fn, options) { return stream.Readable.prototype.filter.call(source, fn, options); },
          reduce: function(source, fn, initial, options) { return stream.Readable.prototype.reduce.call(source, fn, initial, options); },
          toArray: function(source, options) { return stream.Readable.prototype.toArray.call(source, options); },
          forEach: function(source, fn, options) { return stream.Readable.prototype.forEach.call(source, fn, options); },
          some: function(source, fn, options) { return stream.Readable.prototype.some.call(source, fn, options); },
          every: function(source, fn, options) { return stream.Readable.prototype.every.call(source, fn, options); },
          find: function(source, fn, options) { return stream.Readable.prototype.find.call(source, fn, options); },
          flatMap: function(source, fn, options) { return stream.Readable.prototype.flatMap.call(source, fn, options); },
          drop: function(source, count, options) { return stream.Readable.prototype.drop.call(source, count, options); },
          take: function(source, count, options) { return stream.Readable.prototype.take.call(source, count, options); }
        };
      } else {
        result = {};
      }
    } else if (name === 'internal/streams/passthrough') {
      result = stream.PassThrough;
    } else if (name === 'internal/streams/pipeline') {
      var streamPipeline = stream.pipeline;
      var streamPromises = stream.promises && stream.promises.pipeline;
      result = function() {
        var args = [];
        for (var pi = 0; pi < arguments.length; pi++) args.push(arguments[pi]);
        var hasCallback = args.length > 0 && typeof args[args.length - 1] === 'function';

        if (typeof streamPipeline !== 'function') {
          throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "pipeline" method is not available');
        }
        if (hasCallback) {
          return streamPipeline.apply(stream, args);
        }

        if (typeof streamPromises === 'function') {
          return streamPromises.apply(stream.promises, args);
        }

        return new Promise(function(resolve, reject) {
          args.push(function(err) {
            if (err) {
              reject(err);
            } else {
              resolve();
            }
          });
          try {
            streamPipeline.apply(stream, args);
          } catch (err) {
            reject(err);
          }
        });
      };
    } else if (name === 'internal/streams/readable') {
      result = stream.Readable;
    } else if (name === 'internal/streams/transform') {
      result = stream.Transform;
    } else if (name === 'internal/streams/utils') {
      result = {
        isDisturbed: stream.isDisturbed || function() { return false; },
        isReadable: stream.isReadable || function() { return false; },
        isWritable: stream.isWritable || function() { return false; },
        isErrored: stream.isErrored || function() { return false; }
      };
    } else if (name === 'internal/streams/writable') {
      result = stream.Writable;
    } else if (name === 'stream/promises') {
      result = stream.promises || {};
    } else if (name === 'stream/consumers') {
      result = stream.consumers || {};
    } else if (name === '_stream_readable') {
      result = stream.Readable;
    } else if (name === '_stream_writable') {
      result = stream.Writable;
    } else if (name === '_stream_duplex') {
      result = stream.Duplex;
    } else if (name === '_stream_transform') {
      result = stream.Transform;
    } else if (name === '_stream_passthrough') {
      result = stream.PassThrough;
    }

    streamInternalModuleCache[name] = result;
    return result;
  }

  function createEventTargetModule() {
    if (eventTargetModuleCache) {
      return eventTargetModuleCache;
    }

    var kEvents = Symbol.for('nodejs.internal.event_target.kEvents');
    var kWeakHandler = Symbol.for('nodejs.internal.event_target.kWeakHandler');

    function ensureEventMap(target) {
      if (!target[kEvents]) {
        Object.defineProperty(target, kEvents, {
          value: new Map(),
          writable: true,
          configurable: true,
          enumerable: false
        });
      }
      return target[kEvents];
    }

    function addTrackedListener(target, type, listener) {
      var map = ensureEventMap(target);
      var listeners = map.get(type);
      if (!listeners) {
        listeners = new Set();
        map.set(type, listeners);
      }
      listeners.add(listener);
    }

    function removeTrackedListener(target, type, listener) {
      var map = target[kEvents];
      if (!map) return;
      var listeners = map.get(type);
      if (!listeners) return;
      listeners.delete(listener);
      if (listeners.size === 0) {
        map.delete(type);
      }
    }

    function EventTarget() {
      this._listeners = {};
      ensureEventMap(this);
    }

    EventTarget.prototype.addEventListener = function(type, listener, options) {
      if (listener === null || listener === undefined) {
        return;
      }
      var capture = false;
      var once = false;
      var passive = false;
      var signal = null;
      if (options === true || options === false) {
        capture = !!options;
      } else if (options !== null && options !== undefined && typeof options === 'object') {
        capture = !!options.capture;
        once = !!options.once;
        passive = !!options.passive;
        if ('signal' in options) {
          var rawSignal = options.signal;
          if (rawSignal === null || (rawSignal !== undefined && !(rawSignal && typeof rawSignal === 'object' && 'aborted' in rawSignal))) {
            throw new TypeError("Failed to execute 'addEventListener': The provided value is not of type 'AbortSignal'.");
          }
          signal = rawSignal || null;
        }
      }
      if (signal && signal.aborted) return;
      if (!this._listeners[type]) this._listeners[type] = [];
      var listeners = this._listeners[type];
      for (var i = 0; i < listeners.length; i++) {
        if (listeners[i].fn === listener && listeners[i].capture === capture) {
          return;
        }
      }
      listeners.push({ fn: listener, once: once, capture: capture, passive: passive, signal: signal });
      addTrackedListener(this, type, listener);
      if (signal && typeof signal.addEventListener === 'function') {
        var self = this;
        signal.addEventListener('abort', function() {
          self.removeEventListener(type, listener, { capture: capture });
        }, { once: true });
      }
    };

    EventTarget.prototype.removeEventListener = function(type, listener, options) {
      if (!this._listeners[type]) return;
      var capture = false;
      if (options === true || options === false) {
        capture = !!options;
      } else if (options && typeof options === 'object') {
        capture = !!options.capture;
      }
      this._listeners[type] = this._listeners[type].filter(function(entry) {
        return !(entry.fn === listener && entry.capture === capture);
      });
      removeTrackedListener(this, type, listener);
    };

    EventTarget.prototype.dispatchEvent = function(event) {
      if (!event || !event.type) return true;
      var listeners = this._listeners[event.type];
      event.target = this;
      event.currentTarget = this;
      if (event.srcElement !== undefined) event.srcElement = this;
      if (event.eventPhase !== undefined) event.eventPhase = 2;
      if (!listeners || listeners.length === 0) {
        event.eventPhase = 0;
        event.currentTarget = null;
        return !event.defaultPrevented;
      }
      var snapshot = listeners.slice();
      for (var i = 0; i < snapshot.length; i++) {
        if (event._stopImmediatePropagation) break;
        var listener = snapshot[i];
        if (!listener) continue;
        if (listener.once) {
          this.removeEventListener(event.type, listener.fn, { capture: listener.capture });
        }
        if (listener.passive) {
          event._passive = true;
        }
        try {
          if (typeof listener.fn === 'function') {
            listener.fn.call(this, event);
          } else if (listener.fn && typeof listener.fn.handleEvent === 'function') {
            listener.fn.handleEvent(event);
          }
        } finally {
          event._passive = false;
        }
      }
      event.eventPhase = 0;
      event.currentTarget = null;
      return !event.defaultPrevented;
    };

    function Event(type, options) {
      if (!(this instanceof Event)) {
        throw new TypeError("Failed to construct 'Event': Please use the 'new' operator.");
      }
      if (arguments.length === 0) {
        throw new TypeError("Failed to construct 'Event': 1 argument required, but only 0 present.");
      }
      this.type = String(type);
      this.bubbles = !!(options && options.bubbles);
      this.cancelable = !!(options && options.cancelable);
      this.composed = !!(options && options.composed);
      this.defaultPrevented = false;
      this.target = null;
      this.currentTarget = null;
      this.srcElement = null;
      this.timeStamp = Date.now();
      this.eventPhase = 0;
      this._cancelBubble = false;
      this._stopPropagation = false;
      this._stopImmediatePropagation = false;
      this._passive = false;
      Object.defineProperty(this, 'isTrusted', {
        get: function() { return false; },
        enumerable: true,
        configurable: false
      });
    }

    Object.defineProperty(Event.prototype, 'cancelBubble', {
      get: function() { return this._cancelBubble; },
      set: function(value) {
        if (value) this._cancelBubble = true;
      },
      enumerable: true,
      configurable: true
    });

    Object.defineProperty(Event.prototype, 'returnValue', {
      get: function() { return !this.defaultPrevented; },
      set: function(value) {
        if (value === false && !this._passive && this.cancelable) {
          this.defaultPrevented = true;
        }
      },
      enumerable: true,
      configurable: true
    });

    Event.prototype.composedPath = function() {
      return this.currentTarget ? [this.currentTarget] : [];
    };
    Event.prototype.preventDefault = function() {
      if (this.cancelable && !this._passive) this.defaultPrevented = true;
    };
    Event.prototype.stopPropagation = function() {
      this._cancelBubble = true;
      this._stopPropagation = true;
    };
    Event.prototype.stopImmediatePropagation = function() {
      this._cancelBubble = true;
      this._stopPropagation = true;
      this._stopImmediatePropagation = true;
    };
    Event.prototype.initEvent = function(type, bubbles, cancelable) {
      this.type = String(type);
      this.bubbles = !!bubbles;
      this.cancelable = !!cancelable;
    };
    Event.NONE = 0;
    Event.CAPTURING_PHASE = 1;
    Event.AT_TARGET = 2;
    Event.BUBBLING_PHASE = 3;
    Object.defineProperty(Event.prototype, Symbol.toStringTag, {
      value: 'Event',
      writable: false,
      configurable: true
    });

    function CustomEvent(type, options) {
      if (!(this instanceof CustomEvent)) {
        throw new TypeError("Failed to construct 'CustomEvent': Please use the 'new' operator.");
      }
      if (arguments.length === 0) {
        throw new TypeError("Failed to construct 'CustomEvent': 1 argument required, but only 0 present.");
      }
      if (typeof type === 'symbol') {
        throw new TypeError('Cannot convert a Symbol value to a string');
      }
      if (options !== undefined && options !== null && typeof options !== 'object') {
        var err = new TypeError('The "options" argument must be of type object. Received type ' + typeof options + ' (' + String(options) + ')');
        err.code = 'ERR_INVALID_ARG_TYPE';
        throw err;
      }
      Event.call(this, type, options);
      Object.defineProperty(this, 'detail', {
        value: options && options.detail !== undefined ? options.detail : null,
        writable: false,
        enumerable: true,
        configurable: false
      });
    }
    CustomEvent.prototype = Object.create(Event.prototype);
    CustomEvent.prototype.constructor = CustomEvent;
    CustomEvent.NONE = 0;
    CustomEvent.CAPTURING_PHASE = 1;
    CustomEvent.AT_TARGET = 2;
    CustomEvent.BUBBLING_PHASE = 3;
    Object.defineProperty(CustomEvent, 'length', { value: 1, writable: false, configurable: true });
    Object.defineProperty(CustomEvent.prototype, Symbol.toStringTag, {
      value: 'CustomEvent',
      writable: false,
      configurable: true
    });

    eventTargetModuleCache = {
      kEvents: kEvents,
      kWeakHandler: kWeakHandler,
      Event: Event,
      EventTarget: EventTarget,
      CustomEvent: CustomEvent,
      NodeEventTarget: EventTarget
    };
    return eventTargetModuleCache;
  }
  function loadInternal(specifier) {
    var normalized = normalizeSpecifier(specifier);
    if (normalized === 'dns/promises') {
      if (!cache[normalized]) {
        var dnsModule = load('dns', '');
        cache[normalized] = {
          exports: dnsModule && dnsModule.promises ? dnsModule.promises : {},
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'readline/promises') {
      if (!cache[normalized]) {
        var readlineModule = load('readline', '');
        cache[normalized] = {
          exports: readlineModule && readlineModule.promises ? readlineModule.promises : {},
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'internal/errors') {
      if (!cache[normalized]) {
        var uv = {};
        try {
          uv = internalModules['internal/test/binding'].internalBinding('uv') || {};
        } catch (_) {}
        function mapDnsErrorCode(code) {
          if (code === uv.UV_EAI_MEMORY || code === undefined) return 'EAI_MEMORY';
          if (code === uv.UV_ENOMEM) return 'ENOMEM';
          return typeof code === 'string' ? code : 'UNKNOWN';
        }
        function DNSException(code, syscall, hostname) {
          this.name = 'Error';
          this.code = mapDnsErrorCode(code);
          this.errno = code;
          this.syscall = syscall;
          if (hostname !== undefined) {
            this.hostname = hostname;
          }
          this.message = String(syscall || '') + ' ' + this.code + (hostname ? ' ' + hostname : '');
          if (typeof Error.captureStackTrace === 'function') {
            Error.captureStackTrace(this, DNSException);
          } else {
            this.stack = new Error(this.message).stack;
          }
          if (typeof this.stack === 'string') {
            this.stack = this.stack.replace(/\n\s*at [^\n]+/, '\n    at Object.<anonymous>');
          }
        }
        DNSException.prototype = Object.create(Error.prototype);
        DNSException.prototype.constructor = DNSException;
        cache[normalized] = {
          exports: { DNSException: DNSException },
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'internal/js_stream_socket') {
      if (!cache[normalized]) {
        var netModule = load('net', '');
        var Socket = netModule && netModule.Socket ? netModule.Socket : function() {};

        function createStreamWrapError() {
          var err = new Error('Stream has StringDecoder set or is in objectMode');
          err.name = 'Error';
          err.code = 'ERR_STREAM_WRAP';
          return err;
        }

        function scheduleStreamWrapCallback(callback, arg) {
          if (typeof callback !== 'function') return;
          if (typeof setImmediate === 'function') {
            setImmediate(function() { callback(arg); });
            return;
          }
          setTimeout(function() { callback(arg); }, 0);
        }

        function toStreamWrapBuffer(chunk) {
          if (chunk == null) return chunk;
          if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
            return chunk;
          }
          if (typeof ArrayBuffer !== 'undefined' &&
              typeof ArrayBuffer.isView === 'function' &&
              ArrayBuffer.isView(chunk)) {
            return Buffer.from(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength || chunk.length || 0);
          }
          return chunk;
        }

        function JSStreamSocket(stream) {
          if (!(this instanceof JSStreamSocket)) return new JSStreamSocket(stream);
          var writableHighWaterMark = stream && stream.writableHighWaterMark != null
            ? stream.writableHighWaterMark
            : (stream && stream._writableState ? stream._writableState.highWaterMark : undefined);
          Socket.call(this, {
            allowHalfOpen: true,
            writableHighWaterMark: writableHighWaterMark
          });

          var self = this;
          this.stream = stream;
          this.readable = !!(stream && stream.readable !== false);
          this.writable = !!(stream && stream.writable !== false);
          this._jsStreamWrapWriting = false;
          this._jsStreamWrapClosed = false;
          this._jsStreamWrapPendingShutdown = null;

          this._handle = {
            _owner: this,
            _closed: false,
            close: function(callback) {
              self.doClose(callback);
            },
            readStart: function() {
              if (stream && typeof stream.resume === 'function') stream.resume();
              return 0;
            },
            readStop: function() {
              if (stream && typeof stream.pause === 'function') stream.pause();
              return 0;
            },
            shutdown: function(req) {
              return self.doShutdown(req);
            }
          };

          if (stream && typeof stream.on === 'function') {
            stream.on('error', function(err) {
              self.emit('error', err);
            });

            var ondata = function(chunk) {
              if (typeof chunk === 'string' ||
                  stream.readableObjectMode === true ||
                  (stream._readableState && stream._readableState.objectMode === true)) {
                if (typeof stream.pause === 'function') stream.pause();
                if (typeof stream.removeListener === 'function') {
                  stream.removeListener('data', ondata);
                }
                self.emit('error', createStreamWrapError());
                return;
              }
              self.emit('data', toStreamWrapBuffer(chunk));
            };

            stream.on('data', ondata);
            stream.on('drain', function() {
              self.emit('drain');
              self._tryShutdownPending();
            });
            stream.once('end', function() {
              self.readable = false;
              self.emit('end');
            });
            stream.once('close', function() {
              if (!self.destroyed) {
                self.destroy();
              }
            });
          }
        }

        JSStreamSocket.prototype = Object.create(Socket.prototype);
        JSStreamSocket.prototype.constructor = JSStreamSocket;

        JSStreamSocket.prototype._finishShutdown = function(req, code) {
          if (req && typeof req.oncomplete === 'function') {
            scheduleStreamWrapCallback(req.oncomplete, code);
          }
        };

        JSStreamSocket.prototype._performShutdown = function(req) {
          var self = this;
          if (this._jsStreamWrapClosed || this.destroyed || !this.stream) {
            this._finishShutdown(req, -1);
            return 0;
          }
          process.nextTick(function() {
            if (!self.stream || self._jsStreamWrapClosed || self.destroyed) {
              self._finishShutdown(req, -1);
              return;
            }
            try {
              self.stream.end(function() {
                self._finishShutdown(req, 0);
              });
            } catch (_shutdownErr) {
              self._finishShutdown(req, -1);
            }
          });
          return 0;
        };

        JSStreamSocket.prototype._tryShutdownPending = function() {
          if (!this._jsStreamWrapPendingShutdown) return;
          if (this._jsStreamWrapWriting) return;
          if (this.stream && this.stream.writableNeedDrain) return;
          var req = this._jsStreamWrapPendingShutdown;
          this._jsStreamWrapPendingShutdown = null;
          this._performShutdown(req);
        };

        JSStreamSocket.prototype.doShutdown = function(req) {
          if (this._jsStreamWrapClosed || this.destroyed) {
            this._finishShutdown(req, -1);
            return 0;
          }
          if (this._jsStreamWrapWriting || (this.stream && this.stream.writableNeedDrain)) {
            this._jsStreamWrapPendingShutdown = req;
            return 0;
          }
          return this._performShutdown(req);
        };

        JSStreamSocket.prototype.doClose = function(callback) {
          this._jsStreamWrapClosed = true;
          if (this._handle) this._handle._closed = true;
          if (this.stream && typeof this.stream.destroy === 'function') {
            try { this.stream.destroy(); } catch (_closeErr) {}
          }
          scheduleStreamWrapCallback(callback);
        };

        JSStreamSocket.prototype.write = function(chunk, encoding, callback) {
          if (typeof encoding === 'function') {
            callback = encoding;
            encoding = undefined;
          }
          if (!this.stream || typeof this.stream.write !== 'function') {
            return Socket.prototype.write.call(this, chunk, encoding, callback);
          }
          var self = this;
          this._jsStreamWrapWriting = true;
          function onwrite(err) {
            self._jsStreamWrapWriting = false;
            if (typeof callback === 'function') callback(err);
            self._tryShutdownPending();
          }
          return this.stream.write(chunk, encoding, onwrite);
        };

        JSStreamSocket.prototype.end = function(chunk, encoding, callback) {
          if (typeof chunk === 'function') {
            callback = chunk;
            chunk = undefined;
            encoding = undefined;
          } else if (typeof encoding === 'function') {
            callback = encoding;
            encoding = undefined;
          }
          if (!this.stream || typeof this.stream.end !== 'function') {
            return Socket.prototype.end.call(this, chunk, encoding, callback);
          }
          this.writable = false;
          this.stream.end(chunk, encoding, callback);
          return this;
        };

        JSStreamSocket.prototype.destroy = function(err) {
          if (this.destroyed) return this;
          this.destroyed = true;
          this._jsStreamWrapClosed = true;
          this.readable = false;
          this.writable = false;
          if (this._handle) {
            this._handle._closed = true;
          }
          if (this.stream && typeof this.stream.destroy === 'function') {
            try { this.stream.destroy(err); } catch (_destroyErr) {}
          }
          this._handle = null;
          if (err) this.emit('error', err);
          var self = this;
          scheduleStreamWrapCallback(function() {
            self.emit('close', !!err);
          });
          return this;
        };

        JSStreamSocket.StreamWrap = JSStreamSocket;

        cache[normalized] = {
          exports: JSStreamSocket,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'internal/readline/utils') {
      if (!cache[normalized]) {
        var readlineModule = load('readline', '');
        var exports = {
          CSI: readlineModule && readlineModule.CSI ? readlineModule.CSI : function(strings) {
            var args = [];
            for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
            var out = '\x1b[';
            for (var j = 0; j < strings.length; j++) {
              out += strings[j];
              if (j < args.length) out += String(args[j]);
            }
            return out;
          }
        };
        exports.default = exports;
        cache[normalized] = {
          exports: exports,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'assert/strict') {
      var assertModule = load('assert', '');
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: assertModule && assertModule.strict ? assertModule.strict : assert,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      if (cache[normalized].exports === undefined && assertModule && assertModule.strict) {
        cache[normalized].exports = assertModule.strict;
      }
      return cache[normalized].exports;
    }
    if (normalized === 'test') {
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: _createNodeTestModule(),
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === '_tls_common') {
      if (!cache[normalized]) {
        var tlsModule = load('tls', '');
        cache[normalized] = {
          exports: {
            checkServerIdentity: tlsModule && tlsModule.checkServerIdentity,
            translatePeerCertificate: tlsModule && tlsModule.translatePeerCertificate
          },
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'internal/event_target') {
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: createEventTargetModule(),
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized.indexOf('internal/util/debuglog') !== -1) {
      normalized = 'internal/util/debuglog';
    }
    var legacyStreamModule = _loadNamedStreamInternal(normalized);
    if (legacyStreamModule !== null && legacyStreamModule !== undefined) {
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: legacyStreamModule,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    var internal = internalModules.hasOwnProperty(normalized) ? internalModules[normalized] : undefined;
    if (!internal) return null;
    if (!cache[normalized]) {
      cache[normalized] = {
        exports: internal,
        loaded: true,
        id: normalized,
        filename: normalized,
        path: '',
        __exactId: idToModuleId(normalized),
        parent: null,
        children: []
      };
    }
    return cache[normalized].exports;
  }
  function isSameModule(a, b) {
    if (!a || !b) return false;
    return a === b;
  }
  function addChild(parent, child) {
    if (!parent || !child) {
      return;
    }
    if (!parent.children) {
      parent.children = [];
    }
    for (var i = 0; i < parent.children.length; i++) {
      if (isSameModule(parent.children[i], child)) {
        return;
      }
    }
    parent.children.push(child);
  }
  function dirname(path) {
    if (!path) {
      return "";
    }
    const normalized = path.replace(/\\/g, "/");
    const idx = normalized.lastIndexOf("/");
    if (idx <= 0) {
      return "";
    }
    return normalized.slice(0, idx);
  }
  // A specifier that names a file location (relative or absolute) rather than
  // a bare package/builtin name. Mirrors resolveModulePath's absolute-path
  // matcher so Windows drive-letter (`C:\`/`C:/`) and UNC (`\\server\...`)
  // absolutes are recognized wherever relative/absolute specifiers must be
  // gated post-resolution (LLP 0013 Policy surface 3 / ENG-22637): the old
  // '.'/'/'-only checks let a restricted package require a sibling by Windows
  // absolute path without the import-policy check (ENG-23481 #8).
  function isPathSpecifier(specifier) {
    if (typeof specifier !== 'string' || !specifier) return false;
    if (specifier.charAt(0) === '.') return true;
    return /^([A-Za-z]:\\|[A-Za-z]:\/|\/|\\\\|\\)/.test(specifier);
  }
  function resolveModulePath(basePath, relativePath) {
    if (!relativePath) {
      return "";
    }
    if (/^([A-Za-z]:\\|[A-Za-z]:\/|\/|\\\\|\\)/.test(relativePath)) {
      return relativePath.replace(/\\/g, "/");
    }
    if (relativePath.indexOf("./") === 0 || relativePath.indexOf("../") === 0) {
      const normalizedBase = dirname(basePath).replace(/\\/g, "/");
      const normalizedRelative = relativePath.replace(/\\/g, "/");
      const stack = normalizedBase ? normalizedBase.split("/") : [];
      const segments = normalizedRelative.split("/");
      for (var i = 0; i < segments.length; i++) {
        var part = segments[i];
        if (!part || part === ".") {
          continue;
        }
        if (part === "..") {
          if (stack.length) {
            stack.pop();
          }
          continue;
        }
        stack.push(part);
      }
      return stack.join("/");
    }
    return relativePath.replace(/\\/g, "/");
  }
  function normalizeHashbang(source) {
    if (!source || source.indexOf("#!") !== 0) {
      return source;
    }
    return "//" + source.slice(2);
  }
  function applyRolldownCjsDirnameBindings(source, bundlePath) {
    // Strip const/let/var __dirname/__filename declarations to avoid
    // clashing with the function parameters injected by the module loader.
    if (source && (source.indexOf("__dirname") !== -1 || source.indexOf("__filename") !== -1)) {
      source = source.replace(/\b(const|let|var)\s+__dirname\s*=[^;\n]+[;\n]/g, '/* __dirname provided by loader */\n');
      source = source.replace(/\b(const|let|var)\s+__filename\s*=[^;\n]+[;\n]/g, '/* __filename provided by loader */\n');
    }
    return source;
  }
  function fixEsmCjsInterop(source) {
    // Patch rolldown's __toCommonJS to return .default with named exports
    // merged, so require('esm-pkg') returns the default export directly.
    if (!source || source.indexOf("__toCommonJS") === -1) return source;
    var marker = "var __toCommonJS = (mod) =>";
    var idx = source.indexOf(marker);
    if (idx === -1) return source;
    var end = source.indexOf(";", idx);
    if (end === -1) return source;
    var replacement = marker + " {\n" +
      "  if (__hasOwnProp.call(mod, 'module.exports')) return mod['module.exports'];\n" +
      "  var __ns = __copyProps(__defProp({}, '__esModule', { value: true }), mod);\n" +
      "  if (__ns.default !== undefined) {\n" +
      "    var __def = __ns.default;\n" +
      "    if (__def && (typeof __def === 'function' || typeof __def === 'object')) {\n" +
      "      var __ks = Object.keys(__ns);\n" +
      "      for (var __ki = 0; __ki < __ks.length; __ki++) {\n" +
      "        if (__ks[__ki] !== 'default' && __ks[__ki] !== '__esModule' && !(__ks[__ki] in __def)) {\n" +
      "          try { __def[__ks[__ki]] = __ns[__ks[__ki]]; } catch(e) {}\n" +
      "        }\n" +
      "      }\n" +
      "    }\n" +
      "    return __def;\n" +
      "  }\n" +
      "  return __ns;\n" +
      "}";
    return source.slice(0, idx) + replacement + source.slice(end + 1);
  }
  function __exactPinProcessStreams() {
    if (typeof process !== 'object' || process === null) {
      return;
    }
    if (process.__exactStreamPinned) {
      return;
    }
    function createWritableProxy(stream) {
      if (!stream) return stream;
      var writeFn = stream.write;
      var proxy = Object.create(stream);
      Object.defineProperty(proxy, "write", {
        configurable: true,
        enumerable: true,
        get: function() { return writeFn; },
        set: function(value) {
          writeFn = value;
        },
      });
      return proxy;
    }
    try {
      if (typeof process.stdout !== 'object' || process.stdout === null) {
        return;
      }
      var stdout = process.stdout;
      var stderr = process.stderr;
      if (stdout && stdout.writable === undefined) {
        stdout = createWritableProxy(stdout);
        if (stdout.writable === undefined) {
          stdout.writable = true;
        }
      }
      if (stdout && typeof stdout.ref !== 'function') {
        stdout.ref = function() { return stdout; };
      }
      if (stdout && typeof stdout.unref !== 'function') {
        stdout.unref = function() { return stdout; };
      }
      Object.defineProperty(process, 'stdout', {
        value: stdout,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      if (stderr) {
        if (stderr.writable === undefined) {
          stderr = createWritableProxy(stderr);
          if (stderr.writable === undefined) {
            stderr.writable = true;
          }
        }
        if (typeof stderr.ref !== 'function') {
          stderr.ref = function() { return stderr; };
        }
        if (typeof stderr.unref !== 'function') {
          stderr.unref = function() { return stderr; };
        }
        Object.defineProperty(process, 'stderr', {
          value: stderr,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      }
      if (process.stdin) {
        if (typeof process.stdin.ref !== 'function') {
          process.stdin.ref = function() { return process.stdin; };
        }
        if (typeof process.stdin.unref !== 'function') {
          process.stdin.unref = function() { return process.stdin; };
        }
        Object.defineProperty(process, 'stdin', {
          value: process.stdin,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      }
      process.__exactStreamPinned = true;
    } catch (_) {
      // Keep module loading resilient if process stream patching is not possible.
    }
  }
  function fixForOfScoping(source) {
    // @ref LLP 0019#tier-2-the-embedded-loader-string-scanner — constrained
    // mirror of the canonical AST transform in
    // packages/ibex-devtools/src/scripts/hermes-compat.mjs: it runs inside
    // the Hermes bootstrap with no parser, so it approximates the authority's
    // rewrite set with line-based analysis (bails must stay coarser, never
    // looser) while emitting the same iterator-protocol output shape.
    // Behavioral agreement with the AST tier is enforced by the shared corpus
    // through the real binary (run-hermes-compat-loader.mjs, ENG-22989);
    // divergences must be encoded there explicitly.
    //
    // Fast-path gate (ENG-22546): presence checks only. The old single-regex
    // gate matched the whole header with [^)]*, so a ")" inside a string or
    // regex literal in the binding (for (const { label = "(none)" } of xs))
    // hid the "of", the file was skipped entirely, and the Hermes for-of
    // closure pitfall survived. The content-aware line parse below decides
    // what actually rewrites; the gate only has to be cheap and never miss.
    if (!source || !/\bfor\s*\(\s*(?:const|let)\b/.test(source) || !/\bof\b/.test(source)) {
      return source;
    }
    var isSimpleBinding = /^[A-Za-z_$][\w$]*$/;
    function splitForOfBinding(inner) {
      var declMatch = inner.match(/^(const|let)\s+/);
      if (!declMatch) return null;
      var text = inner.slice(declMatch[0].length);
      var depthParen = 0;
      var depthBrace = 0;
      var depthBracket = 0;
      var lastCode = -1;
      for (var index = 0; index < text.length; index++) {
        // Skip strings, templates (with ${...} interpolations), regex
        // literals, and comments whole (ENG-22536): a quote inside a regex
        // (/['"]/) or a backtick inside an interpolation (`${"`"}`) used to
        // flip the flat string skip and mis-split the binding.
        var contentEnd = indexAfterContentToken(text, index, lastCode);
        if (contentEnd !== -1) {
          lastCode = contentEnd - 1;
          index = contentEnd - 1;
          continue;
        }
        var ch = text.charCodeAt(index);
        if (ch === 40) depthParen++;
        else if (ch === 41) depthParen--;
        else if (ch === 123) depthBrace++;
        else if (ch === 125) depthBrace--;
        else if (ch === 91) depthBracket++;
        else if (ch === 93) depthBracket--;
        if (depthParen === 0 && depthBrace === 0 && depthBracket === 0 && text.slice(index, index + 4) === " of ") {
          return {
            kind: declMatch[1],
            binding: text.slice(0, index).replace(/^\s+|\s+$/g, ""),
            expr: text.slice(index + 4).replace(/^\s+|\s+$/g, "")
          };
        }
        if (ch !== 32 && ch !== 9) {
          lastCode = index;
        }
      }
      return null;
    }
    // Recursive chunk rewriter (ENG-22558). At the top level `source` is the
    // whole file; on recursion it is the ORIGINAL body text of a loop that is
    // about to be wrapped, so nested for-of loops get their own rewrite
    // instead of being emitted raw (where the Hermes function-scoped-const
    // closure pitfall survived one level down). Recursion always runs on the
    // pre-wrap body, so the generated iterator-protocol wrapper header is
    // never re-scanned. `namePrefix` keeps the generated
    // __exactForOfValue<...> temporaries unique across nesting levels: each
    // recursion appends the enclosing header's line index, so the name
    // encodes the loop's path ("" at top level, "5_" inside the loop at line
    // 5, "5_2_" one level deeper, ...).
    function rewriteForOfChunk(source, namePrefix) {
      var lines = source.split("\n");
      // Line-start offsets into the original source, so the body brace-matcher
      // below can walk `source` directly (no per-header slice/join copies).
      var lineStarts = new Array(lines.length);
      var offset = 0;
      for (var ls = 0; ls < lines.length; ls++) {
        lineStarts[ls] = offset;
        offset += lines[ls].length + 1;
      }
      var out = [];
      var i = 0;
      // File-wide content state (ENG-22546): fixForOfScoping used to be purely
      // line-based, so a line inside multi-line template-literal text that
      // merely looked like `for (const x of y) {` was rewritten, corrupting the
      // template content. Same approach as transformEsmToCjs's moduleScanState:
      // every line emitted unchanged advances the state, and a rewrite is only
      // considered when the line starts in code context.
      var fileState = createDelimiterScanState();
      while (i < lines.length) {
        var line = lines[i];
        // Match: for (const/let BINDING of EXPR) {
        // Use precise parsing instead of regex to handle nested parens correctly
        var trimmed = line.replace(/^\s*/, "");
        var indent = line.slice(0, line.length - trimmed.length);
        if (delimiterScanInContent(fileState) || !/^for\s*\(/.test(trimmed)) {
          scanDelimiterLine(line, fileState);
          out.push(line);
          i++;
          continue;
        }
        // Find the balanced closing paren for the for(...)
        var forStart = trimmed.indexOf("(");
        if (forStart === -1) { scanDelimiterLine(line, fileState); out.push(line); i++; continue; }
        var parenDepth = 0;
        var forEnd = -1;
        var headLastCode = -1;
        for (var fi = forStart; fi < trimmed.length; fi++) {
          // Content-aware skip (ENG-22536): quotes inside regex literals or
          // backticks inside template interpolations used to open a bogus
          // string state that hid the closing paren.
          var headContentEnd = indexAfterContentToken(trimmed, fi, headLastCode);
          if (headContentEnd !== -1) {
            headLastCode = headContentEnd - 1;
            fi = headContentEnd - 1;
            continue;
          }
          var fc = trimmed.charCodeAt(fi);
          if (fc === 40) parenDepth++;
          else if (fc === 41) { parenDepth--; if (parenDepth === 0) { forEnd = fi; break; } }
          if (fc !== 32 && fc !== 9) headLastCode = fi;
        }
        if (forEnd === -1) { scanDelimiterLine(line, fileState); out.push(line); i++; continue; }
        var inner = trimmed.slice(forStart + 1, forEnd).replace(/^\s+|\s+$/g, "");
        var parts = splitForOfBinding(inner);
        if (!parts || !parts.binding || !parts.expr) { scanDelimiterLine(line, fileState); out.push(line); i++; continue; }
        var binding = parts.binding;
        var expr = parts.expr;
        var kind = parts.kind;
        // Rest of line after for(...) must be just "{"
        var afterFor = trimmed.slice(forEnd + 1).replace(/^\s+|\s+$/g, "");
        if (afterFor !== "{") { scanDelimiterLine(line, fileState); out.push(line); i++; continue; }
        // Find the matching closing brace with the shared content-aware walk
        // (ENG-22546). The old per-line matcher treated backticks as flat
        // strings with no ${...} awareness, so a backtick inside an
        // interpolation (`${"`"}`) or braces inside interpolation code desynced
        // the depth count, and a template spanning lines hid real braces.
        // indexAfterContentToken skips strings, comments, regex literals, and
        // whole template literals (interpolations and nesting included) over
        // the original source, so multi-line content is handled by
        // construction.
        var bodyStart = i + 1 < lines.length ? lineStarts[i + 1] : source.length;
        var depth = 1;
        var closeIndex = -1;
        var bodyLastCode = -1;
        for (var bi = bodyStart; bi < source.length; bi++) {
          var bodyContentEnd = indexAfterContentToken(source, bi, bodyLastCode);
          if (bodyContentEnd !== -1) {
            bodyLastCode = bodyContentEnd - 1;
            bi = bodyContentEnd - 1;
            continue;
          }
          var bc = source.charCodeAt(bi);
          if (bc === 123) depth++;
          else if (bc === 125) {
            depth--;
            if (depth === 0) { closeIndex = bi; break; }
          }
          if (bc !== 32 && bc !== 9 && bc !== 10 && bc !== 13) bodyLastCode = bi;
        }
        if (closeIndex === -1) { scanDelimiterLine(line, fileState); out.push(line); i++; continue; }
        var closeLine = i + 1;
        while (closeLine + 1 < lines.length && lineStarts[closeLine + 1] <= closeIndex) {
          closeLine++;
        }
        // Only rewrite when the closing line is a bare "}". The old matcher
        // replaced the whole closing line with "}, this);", silently dropping
        // any other code sharing that line; bail conservatively instead.
        if (lines[closeLine].replace(/^\s+|\s+$/g, "") !== "}") {
          scanDelimiterLine(line, fileState);
          out.push(line);
          i++;
          continue;
        }
        var bodyLines = lines.slice(i + 1, closeLine);
        // Bail scan (ENG-22990, converged with the canonical AST transform's
        // hasUnsafeControlFlow/hasHoistingHazard as far as a line scanner
        // allows; see packages/ibex-devtools/src/scripts/hermes-compat.mjs):
        // - return/continue/break/yield/await: moving the body into a
        //   per-iteration function would change control flow. Load-bearing
        //   since before ENG-22546. break/continue are bare keyword matches
        //   like the others (ENG-23137): the old /\b(break|continue)\s*[;\n}]/
        //   ran on split("\n") lines, so the \n alternative never matched and
        //   an ASI bare `break` at end of line (or a labeled `break outer`)
        //   did NOT bail — the body then moved into an arrow function where
        //   break/continue are illegal, turning valid semicolon-free code
        //   into a SyntaxError. Coarser matching only costs a bailed rewrite
        //   (capture-last), the safe direction per LLP 0019.
        // - var declarations and line-leading function declarations: the body
        //   moves into a per-iteration function, so a `var` would no longer
        //   hoist to the enclosing function and a sloppy-mode function
        //   declaration would lose its function-scope binding (the AST twin's
        //   hoisting-hazard bail). The line regexes are coarser than the AST
        //   walk — a `var` inside a nested closure in the body also bails —
        //   but coarse-bail only costs the capture-last pitfall for that loop,
        //   which is strictly less wrong than breaking hoisting semantics.
        // - a body-top-level let/const redeclaring a simple loop binding would
        //   be a redeclaration in the generated wrapper block; bail like the
        //   AST twin's bodyRedeclaresBoundNames (destructured bindings keep
        //   the pre-existing coarseness: their names are not extracted here).
        var bailRewrite = false;
        var redeclareRe = isSimpleBinding.test(binding)
          ? new RegExp("^\\s*(?:let|const)\\s+" + binding + "\\b")
          : null;
        for (var b = 0; b < bodyLines.length; b++) {
          var bl = bodyLines[b];
          if (/\b(break|continue)\b/.test(bl) || /\byield\b/.test(bl) || /\bawait\b/.test(bl) || /\breturn\b/.test(bl)) {
            bailRewrite = true;
            break;
          }
          if (/\bvar\b/.test(bl) || /^\s*(?:async\s+)?function\b/.test(bl)) {
            bailRewrite = true;
            break;
          }
          if (redeclareRe && redeclareRe.test(bl)) {
            bailRewrite = true;
            break;
          }
        }
        if (bailRewrite) { scanDelimiterLine(line, fileState); out.push(line); i++; continue; }
        // Rewrite nested for-of loops inside the body before wrapping it
        // (ENG-22558). This only ADDS inner rewrites where the outer already
        // rewrites: the bail scan above ran over every raw body line — a
        // superset of any inner loop's body lines — so an inner rewrite can
        // never hit a shared bail keyword the outer scan did not already bail
        // on, and the outer's bail decision is untouched. (The binding-specific
        // redeclare bail can make an INNER loop bail where the outer did not;
        // that only leaves the inner loop raw, which is always safe.)
        var emitBodyLines = bodyLines;
        if (bodyLines.length > 0) {
          var bodyText = bodyLines.join("\n");
          if (/\bfor\s*\(\s*(?:const|let)\b/.test(bodyText) && /\bof\b/.test(bodyText)) {
            var rewrittenBody = rewriteForOfChunk(bodyText, namePrefix + i + "_");
            if (rewrittenBody !== bodyText) {
              emitBodyLines = rewrittenBody.split("\n");
            }
          }
        }
        // Emit the ENG-22569 iterator-protocol shape (ENG-22990), converging
        // on the canonical AST transform's output (hermes-compat.mjs): the
        // body lives in an arrow function allocated once and invoked with the
        // current iteration's value, so the let/const binding re-declared
        // inside it gets a fresh binding per call on every Hermes
        // configuration, while the arrow preserves `this`, `arguments`,
        // `super`, and `new.target` (the old
        // `Array.from(expr).forEach(function(...){...}, this)` shape broke
        // `arguments`/`super`/`new.target` and — by materializing the
        // iterable up front — lazy iterators, mutation-during-iteration, and
        // IteratorClose ordering). The explicit protocol keeps live iteration,
        // and the catch block runs IteratorClose (iterator.return) when the
        // body throws, matching native for-of (ENG-23036); per spec the
        // body's error wins over a throwing return().
        var suffix = namePrefix + i;
        var iterName = "__exactForOfIterator" + suffix;
        var stepName = "__exactForOfStep" + suffix;
        var valueName = "__exactForOfValue" + suffix;
        var bodyFnName = "__exactForOfBody" + suffix;
        var errorName = "__exactForOfError" + suffix;
        var returnName = "__exactForOfReturn" + suffix;
        var ignoreName = "__exactForOfIgnore" + suffix;
        // The binding declaration rides on the header line (not a line of its
        // own) so the rewrite replaces the original header/body/close lines
        // one-for-one and stack-trace line numbers inside and after the loop
        // stay aligned with the source (ENG-23481 #11).
        out.push(
          indent + "{ const " + iterName + " = (" + expr + ")[Symbol.iterator](); " +
          "const " + bodyFnName + " = (" + valueName + ") => { " +
          kind + " " + binding + " = " + valueName + ";"
        );
        for (var b2 = 0; b2 < emitBodyLines.length; b2++) {
          out.push(emitBodyLines[b2]);
        }
        out.push(
          indent + "}; for (;;) { const " + stepName + " = " + iterName + ".next(); " +
          "if (" + stepName + ".done) break; " +
          "try { " + bodyFnName + "(" + stepName + ".value); } " +
          "catch (" + errorName + ") { " +
          "const " + returnName + " = " + iterName + ".return; " +
          "if (typeof " + returnName + " === 'function') { " +
          "try { " + returnName + ".call(" + iterName + "); } catch (" + ignoreName + ") {} } " +
          "throw " + errorName + "; } } }"
        );
        // Advance the file-wide state over the consumed original lines so the
        // lines after the loop are classified against the true source state.
        for (var s = i; s <= closeLine; s++) {
          scanDelimiterLine(lines[s], fileState);
        }
        i = closeLine + 1;
      }
      return out.join("\n");
    }
    return rewriteForOfChunk(source, "");
  }
  function aliasNodePathGlobals(source) {
    if (!source || (source.indexOf("__dirname") === -1 && source.indexOf("__filename") === -1)) {
      return source;
    }
    return source.replace(/\b__dirname\b/g, "globalThis.__dirname").replace(/\b__filename\b/g, "globalThis.__filename");
  }
  // Replacements for well-known `import.meta.<prop>` properties. Any other
  // property (and bare `import.meta`) falls back to globalThis.__exactImportMeta.
  var importMetaPropertyReplacements = {
    // Mirror Node's pathToFileURL shape: forward slashes and a guaranteed
    // leading slash, so a Windows __filename ('C:\\app\\x.js') becomes
    // 'file:///C:/app/x.js' instead of the malformed 'file://C:\\app\\x.js'
    // the plain concatenation produced (new URL(import.meta.url) and
    // fileURLToPath both choke on that) (ENG-23481 #12). POSIX paths already
    // start with '/' and contain no backslashes, so they are unchanged.
    url: '("file://" + (__filename.charAt(0) === "/" ? __filename : "/" + __filename).replace(/\\\\/g, "/"))',
    path: "__filename",
    filename: "__filename",
    file: "(typeof __filename !== 'undefined' ? __filename.split('/').pop() : '')",
    dirname: "__dirname",
    dir: "__dirname",
    main: "(typeof __filename !== 'undefined' && __filename === (globalThis.process && globalThis.process.argv && globalThis.process.argv[1]))",
    require: "require"
  };
  function transformImportMeta(source) {
    if (!source || source.indexOf("import.meta") === -1) {
      return source;
    }
    // Rewrite import.meta only in code context (ENG-22536). The old
    // context-free regex replaces rewrote occurrences inside string literals
    // and comments too — a log line quoting "import.meta.url" became
    // ("file://" + __filename). Same walk as transformDynamicImport: skip
    // strings, comments, and regex literals; template-literal text is skipped
    // via the template-context stack while ${...} interpolation code keeps
    // being scanned and rewritten.
    var result = "";
    var i = 0;
    var len = source.length;
    var templateStack = [];
    var lastCode = -1;
    while (i < len) {
      var ch = source[i];
      var top = templateStack.length ? templateStack[templateStack.length - 1] : null;
      if (top === -1) {
        // Inside template-literal text.
        if (ch === '\\') {
          result += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        if (ch === '`') {
          result += ch;
          templateStack.pop();
          lastCode = i;
          i++;
          continue;
        }
        if (ch === '$' && source[i + 1] === '{') {
          result += '${';
          templateStack.push(0);
          lastCode = -1;
          i += 2;
          continue;
        }
        result += ch;
        i++;
        continue;
      }
      if (ch === '/' && source[i + 1] === '/') {
        var lineEnd = source.indexOf('\n', i);
        if (lineEnd === -1) { lineEnd = len; }
        result += source.slice(i, lineEnd);
        i = lineEnd;
        continue;
      }
      if (ch === '/' && source[i + 1] === '*') {
        var blockEnd = source.indexOf('*/', i + 2);
        blockEnd = blockEnd === -1 ? len : blockEnd + 2;
        result += source.slice(i, blockEnd);
        i = blockEnd;
        continue;
      }
      if (ch === '/') {
        var regexEnd = indexAfterRegexLiteral(source, i, lastCode);
        if (regexEnd !== -1) {
          result += source.slice(i, regexEnd);
          lastCode = regexEnd - 1;
          i = regexEnd;
          continue;
        }
      }
      if (ch === '"' || ch === "'") {
        var quote = ch;
        var j = i + 1;
        while (j < len) {
          if (source[j] === '\\') { j += 2; continue; }
          if (source[j] === quote) { j++; break; }
          j++;
        }
        result += source.slice(i, j);
        lastCode = j - 1;
        i = j;
        continue;
      }
      if (ch === '`') {
        result += ch;
        templateStack.push(-1);
        i++;
        continue;
      }
      if (top !== null) {
        // Inside ${...} interpolation code: balance braces so the closing
        // `}` returns to template text instead of being treated as code.
        if (ch === '{') {
          templateStack[templateStack.length - 1] = top + 1;
        } else if (ch === '}') {
          if (top === 0) {
            templateStack.pop();
            result += ch;
            i++;
            continue;
          }
          templateStack[templateStack.length - 1] = top - 1;
        }
      }
      if (
        ch === 'i' &&
        source.slice(i, i + 11) === 'import.meta' &&
        (i === 0 || !/[A-Za-z0-9_$.]/.test(source[i - 1])) &&
        !/[A-Za-z0-9_$]/.test(source[i + 11] || '')
      ) {
        var matchEnd = i + 11;
        var replacement = null;
        if (source[matchEnd] === '.') {
          var propEnd = matchEnd + 1;
          while (propEnd < len && /[A-Za-z0-9_$]/.test(source[propEnd])) {
            propEnd++;
          }
          var prop = source.slice(matchEnd + 1, propEnd);
          if (Object.prototype.hasOwnProperty.call(importMetaPropertyReplacements, prop)) {
            replacement = importMetaPropertyReplacements[prop];
            matchEnd = propEnd;
          }
        }
        if (replacement === null) {
          // Bare import.meta (or an unknown property, left as a property
          // access on the polyfill object).
          replacement = 'globalThis.__exactImportMeta';
        }
        result += replacement;
        lastCode = matchEnd - 1;
        i = matchEnd;
        continue;
      }
      if (ch !== ' ' && ch !== '\t' && ch !== '\r' && ch !== '\n') {
        lastCode = i;
      }
      result += ch;
      i++;
    }
    return result;
  }
  // --- Shared lexical-scanner helpers (ENG-22528) ---------------------------
  // transformDynamicImport and the transformEsmToCjs statement scanners below
  // all walk raw module source character by character. They must agree on
  // what is code and what is string/comment/regex content, or an apostrophe
  // inside a regex literal (/['"]/) or a backtick inside a template
  // interpolation (`${"`"}`) opens a bogus skip that swallows real code —
  // the same failure class ENG-22514/ENG-22520 fixed for comments.
  //
  // Keywords after which a `/` begins a regex literal rather than division
  // (the usual prior-token list from minimal ES scanners).
  var regexPrecedingKeywords = [
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await"
  ];
  // Given the index of the previous significant (non-whitespace, non-comment)
  // code character — or -1 when there is none — decide whether a `/` here can
  // begin a regex literal. Errs toward division (the scanners' old behavior)
  // whenever the prior token plausibly ends an expression.
  function isRegexAllowedAfter(source, lastCodeIndex) {
    if (lastCodeIndex < 0) {
      return true;
    }
    var ch = source.charAt(lastCodeIndex);
    if (ch === ")" || ch === "]" || ch === "'" || ch === '"' || ch === "`" || ch === ".") {
      return false;
    }
    if (/[A-Za-z0-9_$]/.test(ch)) {
      var wordStart = lastCodeIndex;
      while (wordStart > 0 && /[A-Za-z0-9_$]/.test(source.charAt(wordStart - 1))) {
        wordStart--;
      }
      if (wordStart > 0 && source.charAt(wordStart - 1) === ".") {
        // Property access (`foo.in`) — never a regex position.
        return false;
      }
      var word = source.slice(wordStart, lastCodeIndex + 1);
      if (/^[0-9]/.test(word)) {
        return false;
      }
      return regexPrecedingKeywords.indexOf(word) !== -1;
    }
    if ((ch === "+" || ch === "-") && source.charAt(lastCodeIndex - 1) === ch) {
      // Postfix `++`/`--`: `n++ / 2` is division; `++/re/` cannot parse.
      return false;
    }
    return true;
  }
  // If the `/` at slashIndex (already known not to start a comment) begins a
  // regex literal, return the index just past the literal including flags;
  // otherwise return -1 and the caller treats it as plain code (division).
  // Conservative by construction: regex literals cannot contain unescaped
  // line terminators, so when no closing `/` exists on the same line this
  // falls back to -1 — i.e. to the scanners' old behavior.
  function indexAfterRegexLiteral(source, slashIndex, lastCodeIndex) {
    if (!isRegexAllowedAfter(source, lastCodeIndex)) {
      return -1;
    }
    var len = source.length;
    var i = slashIndex + 1;
    var inClass = false;
    while (i < len) {
      var ch = source.charAt(i);
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch === "\n" || ch === "\r") {
        return -1;
      }
      if (ch === "[") {
        inClass = true;
      } else if (ch === "]") {
        inClass = false;
      } else if (ch === "/" && !inClass) {
        i++;
        while (i < len && /[A-Za-z]/.test(source.charAt(i))) {
          i++;
        }
        return i;
      }
      i++;
    }
    return -1;
  }
  // Return the index just past the template literal whose opening backtick is
  // at backtickIndex. Handles escapes and ${...} interpolations — which are
  // real code context and may nest strings, comments, regexes, and further
  // template literals. Returns source.length for unterminated input.
  function indexAfterTemplateLiteral(source, backtickIndex) {
    var len = source.length;
    var i = backtickIndex + 1;
    while (i < len) {
      var ch = source.charAt(i);
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch === "`") {
        return i + 1;
      }
      if (ch === "$" && source.charAt(i + 1) === "{") {
        i = indexAfterTemplateInterpolation(source, i + 2);
        continue;
      }
      i++;
    }
    return len;
  }
  // Return the index just past the `}` that closes the ${...} interpolation
  // whose code starts at codeStart. Skips nested strings, comments, template
  // literals, regexes, and balanced braces.
  function indexAfterTemplateInterpolation(source, codeStart) {
    var len = source.length;
    var depth = 0;
    var lastCode = -1;
    var i = codeStart;
    while (i < len) {
      var ch = source.charAt(i);
      var next = source.charAt(i + 1);
      if (ch === "/" && next === "/") {
        var lineEnd = source.indexOf("\n", i);
        i = lineEnd === -1 ? len : lineEnd;
        continue;
      }
      if (ch === "/" && next === "*") {
        var blockEnd = source.indexOf("*/", i + 2);
        i = blockEnd === -1 ? len : blockEnd + 2;
        continue;
      }
      if (ch === "/") {
        var regexEnd = indexAfterRegexLiteral(source, i, lastCode);
        if (regexEnd !== -1) {
          lastCode = regexEnd - 1;
          i = regexEnd;
          continue;
        }
      }
      if (ch === "'" || ch === '"') {
        var j = i + 1;
        while (j < len) {
          if (source.charAt(j) === "\\") {
            j += 2;
            continue;
          }
          if (source.charAt(j) === ch) {
            j++;
            break;
          }
          j++;
        }
        lastCode = j - 1;
        i = j;
        continue;
      }
      if (ch === "`") {
        i = indexAfterTemplateLiteral(source, i);
        lastCode = i - 1;
        continue;
      }
      if (ch === "{") {
        depth++;
      } else if (ch === "}") {
        if (depth === 0) {
          return i + 1;
        }
        depth--;
      }
      if (ch !== " " && ch !== "\t" && ch !== "\r" && ch !== "\n") {
        lastCode = i;
      }
      i++;
    }
    return len;
  }
  // If the character at `index` opens string/template/regex/comment content,
  // return the index just past that content; otherwise return -1 and the
  // caller treats the character as plain code (ENG-22536). `lastCodeIndex` is
  // the prior-token context for the regex-vs-division decision. Template
  // literals are skipped whole (their ${...} interpolations included), which
  // is correct for balance/split scans: a terminated template contributes no
  // code-context delimiters, and an unterminated one runs the skip to the end
  // of the input so callers bail conservatively.
  function indexAfterContentToken(source, index, lastCodeIndex) {
    var ch = source.charAt(index);
    if (ch === '"' || ch === "'") {
      var len = source.length;
      var j = index + 1;
      while (j < len) {
        if (source.charAt(j) === "\\") {
          j += 2;
          continue;
        }
        if (source.charAt(j) === ch) {
          return j + 1;
        }
        j++;
      }
      return len;
    }
    if (ch === "`") {
      return indexAfterTemplateLiteral(source, index);
    }
    if (ch === "/") {
      var next = source.charAt(index + 1);
      if (next === "/") {
        var lineEnd = source.indexOf("\n", index);
        return lineEnd === -1 ? source.length : lineEnd;
      }
      if (next === "*") {
        var blockEnd = source.indexOf("*/", index + 2);
        return blockEnd === -1 ? source.length : blockEnd + 2;
      }
      return indexAfterRegexLiteral(source, index, lastCodeIndex);
    }
    return -1;
  }
  // Content-aware, line-at-a-time delimiter tracking (ENG-22536; hoisted here
  // for ENG-22546). One scan state persists across a whole file: block
  // comments and template literals may span lines, a `;` at the end of a line
  // that is really template text must not close a pending export, and a line
  // that merely LOOKS like a module statement (or a for-of header) while
  // inside multi-line template text must not be rewritten at all.
  // templateStack entries are -1 while inside template-literal text, or the
  // unmatched-`{` depth while inside a ${...} interpolation (same convention
  // as transformDynamicImport). Used by transformEsmToCjs (moduleScanState)
  // and fixForOfScoping (its file-wide content gate).
  function createDelimiterScanState() {
    return { balance: 0, templateStack: [], inBlockComment: false };
  }
  function delimiterScanInContent(state) {
    return state.inBlockComment || state.templateStack.length > 0;
  }
  function scanDelimiterLine(value, state) {
    var text = String(value || "");
    var len = text.length;
    var i = 0;
    var lastCode = -1;
    while (i < len) {
      var ch = text.charAt(i);
      if (state.inBlockComment) {
        var blockEnd = text.indexOf("*/", i);
        if (blockEnd === -1) {
          return;
        }
        state.inBlockComment = false;
        i = blockEnd + 2;
        continue;
      }
      var top = state.templateStack.length
        ? state.templateStack[state.templateStack.length - 1]
        : null;
      if (top === -1) {
        // Inside template-literal text.
        if (ch === "\\") {
          i += 2;
          continue;
        }
        if (ch === "`") {
          state.templateStack.pop();
          lastCode = i;
          i++;
          continue;
        }
        if (ch === "$" && text.charAt(i + 1) === "{") {
          state.templateStack.push(0);
          lastCode = -1;
          i += 2;
          continue;
        }
        i++;
        continue;
      }
      var next = text.charAt(i + 1);
      if (ch === "/" && next === "/") {
        var lineEnd = text.indexOf("\n", i);
        if (lineEnd === -1) {
          return;
        }
        i = lineEnd + 1;
        continue;
      }
      if (ch === "/" && next === "*") {
        state.inBlockComment = true;
        i += 2;
        continue;
      }
      if (ch === "/") {
        var regexEnd = indexAfterRegexLiteral(text, i, lastCode);
        if (regexEnd !== -1) {
          lastCode = regexEnd - 1;
          i = regexEnd;
          continue;
        }
      }
      if (ch === '"' || ch === "'") {
        var j = i + 1;
        while (j < len) {
          if (text.charAt(j) === "\\") {
            j += 2;
            continue;
          }
          if (text.charAt(j) === ch) {
            j++;
            break;
          }
          j++;
        }
        lastCode = j - 1;
        i = j;
        continue;
      }
      if (ch === "`") {
        state.templateStack.push(-1);
        i++;
        continue;
      }
      if (top !== null) {
        // Inside ${...} interpolation code: braces there balance the
        // interpolation itself, not the surrounding statement.
        if (ch === "{") {
          state.templateStack[state.templateStack.length - 1] = top + 1;
          lastCode = i;
          i++;
          continue;
        }
        if (ch === "}") {
          if (top === 0) {
            state.templateStack.pop();
          } else {
            state.templateStack[state.templateStack.length - 1] = top - 1;
          }
          lastCode = i;
          i++;
          continue;
        }
      }
      if (ch === "{" || ch === "(" || ch === "[") {
        state.balance++;
      } else if (ch === "}" || ch === ")" || ch === "]") {
        state.balance--;
      }
      if (ch !== " " && ch !== "\t" && ch !== "\r" && ch !== "\n") {
        lastCode = i;
      }
      i++;
    }
  }
  function transformDynamicImport(source) {
    if (!source || source.indexOf("import(") === -1) {
      return source;
    }
    // Replace dynamic import() calls with the module-local helper that closes
    // over this module's filename/referrer. A global import polyfill cannot
    // resolve `import("./local.js")` relative to the caller. (ENG-22718)
    // Skip replacements inside string literals to avoid breaking error messages etc.
    var result = "";
    var i = 0;
    var len = source.length;
    // Template-context stack (ENG-22528): each entry is -1 while inside the
    // literal text of a template, or the current unmatched-`{` depth while
    // inside a ${...} interpolation. Interpolation code is real code context:
    // an import() there must be rewritten, and a quote or backtick inside it
    // must not terminate the outer template scan.
    var templateStack = [];
    // Index of the last significant (non-whitespace, non-comment) code
    // character — the prior-token context for regex-vs-division decisions.
    var lastCode = -1;
    while (i < len) {
      var ch = source[i];
      var top = templateStack.length ? templateStack[templateStack.length - 1] : null;
      if (top === -1) {
        // Inside template-literal text.
        if (ch === '\\') {
          result += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        if (ch === '`') {
          result += ch;
          templateStack.pop();
          lastCode = i;
          i++;
          continue;
        }
        if (ch === '$' && source[i + 1] === '{') {
          result += '${';
          templateStack.push(0);
          lastCode = -1;
          i += 2;
          continue;
        }
        result += ch;
        i++;
        continue;
      }
      // Skip comments verbatim. Without this, an apostrophe inside a comment
      // (e.g. "the gateway's auto tier") opens a bogus string skip that can
      // swallow kilobytes of code — leaving later import() calls unrewritten,
      // which Hermes then rejects at eval time (ENG-22520, same class as the
      // ENG-22514 transformEsmToCjs comment bugs).
      if (ch === '/' && source[i + 1] === '/') {
        var lineEnd = source.indexOf('\n', i);
        if (lineEnd === -1) { lineEnd = len; }
        result += source.slice(i, lineEnd);
        i = lineEnd;
        continue;
      }
      if (ch === '/' && source[i + 1] === '*') {
        var blockEnd = source.indexOf('*/', i + 2);
        blockEnd = blockEnd === -1 ? len : blockEnd + 2;
        result += source.slice(i, blockEnd);
        i = blockEnd;
        continue;
      }
      // Skip regex literals verbatim (ENG-22528). A quote inside a regex
      // such as /['"]/ must not open a bogus string skip.
      if (ch === '/') {
        var regexEnd = indexAfterRegexLiteral(source, i, lastCode);
        if (regexEnd !== -1) {
          result += source.slice(i, regexEnd);
          lastCode = regexEnd - 1;
          i = regexEnd;
          continue;
        }
      }
      // Skip string literals
      if (ch === '"' || ch === "'") {
        var quote = ch;
        var j = i + 1;
        while (j < len) {
          if (source[j] === '\\') { j += 2; continue; }
          if (source[j] === quote) { j++; break; }
          j++;
        }
        result += source.slice(i, j);
        lastCode = j - 1;
        i = j;
        continue;
      }
      // Enter template literals via the template-context stack so that
      // ${...} interpolation code keeps being scanned and rewritten.
      if (ch === '`') {
        result += ch;
        templateStack.push(-1);
        i++;
        continue;
      }
      if (top !== null) {
        // Inside ${...} interpolation code: balance braces so the closing
        // `}` returns to template text instead of being treated as code.
        if (ch === '{') {
          templateStack[templateStack.length - 1] = top + 1;
        } else if (ch === '}') {
          if (top === 0) {
            templateStack.pop();
            result += ch;
            i++;
            continue;
          }
          templateStack[templateStack.length - 1] = top - 1;
        }
      }
      // Check for import( pattern
      if (source.slice(i, i + 7) === 'import(' || source.slice(i, i + 7) === 'import ') {
        var rest = source.slice(i);
        var m = rest.match(/^import\s*\(/);
        if (m) {
          result += '__exactDynamicImport(';
          i += m[0].length;
          lastCode = i - 1;
          continue;
        }
      }
      if (ch !== ' ' && ch !== '\t' && ch !== '\r' && ch !== '\n') {
        lastCode = i;
      }
      result += ch;
      i++;
    }
    return result;
  }
  function transformEsmToCjs(source) {
    if (!source) {
      return "";
    }
    var splitInlineModuleStatements = function(text) {
      var sourceText = String(text || "");
      var result = "";
      var inSingle = false;
      var inDouble = false;
      var inLineComment = false;
      var inBlockComment = false;
      // Prior-token index for regex-vs-division decisions (ENG-22528).
      var lastCodeIndex = -1;
      for (var cursor = 0; cursor < sourceText.length; cursor++) {
        var ch = sourceText.charAt(cursor);
        var next = sourceText.charAt(cursor + 1);
        if (inLineComment) {
          result += ch;
          if (ch === "\n") {
            inLineComment = false;
          }
          continue;
        }
        if (inBlockComment) {
          result += ch;
          if (ch === "*" && next === "/") {
            result += next;
            cursor++;
            inBlockComment = false;
          }
          continue;
        }
        if (inSingle) {
          result += ch;
          if (ch === "\\") {
            result += next;
            cursor++;
            continue;
          }
          if (ch === "'") {
            inSingle = false;
            lastCodeIndex = cursor;
          }
          continue;
        }
        if (inDouble) {
          result += ch;
          if (ch === "\\") {
            result += next;
            cursor++;
            continue;
          }
          if (ch === '"') {
            inDouble = false;
            lastCodeIndex = cursor;
          }
          continue;
        }
        if (ch === "/" && next === "/") {
          result += ch + next;
          cursor++;
          inLineComment = true;
          continue;
        }
        if (ch === "/" && next === "*") {
          result += ch + next;
          cursor++;
          inBlockComment = true;
          continue;
        }
        // Skip regex literals verbatim (ENG-22528): a quote inside /['"]/
        // must not open a bogus string state that swallows a later
        // `;import`/`;export` boundary.
        if (ch === "/") {
          var regexEnd = indexAfterRegexLiteral(sourceText, cursor, lastCodeIndex);
          if (regexEnd !== -1) {
            result += sourceText.slice(cursor, regexEnd);
            lastCodeIndex = regexEnd - 1;
            cursor = regexEnd - 1;
            continue;
          }
        }
        if (ch === "'") {
          result += ch;
          inSingle = true;
          continue;
        }
        if (ch === '"') {
          result += ch;
          inDouble = true;
          continue;
        }
        // Skip whole template literals, including ${...} interpolations
        // (ENG-22528): a backtick or quote inside an interpolation must not
        // flip the scanner's idea of what is string and what is code.
        if (ch === "`") {
          var templateEnd = indexAfterTemplateLiteral(sourceText, cursor);
          result += sourceText.slice(cursor, templateEnd);
          lastCodeIndex = templateEnd - 1;
          cursor = templateEnd - 1;
          continue;
        }
        if (ch === ";" || ch === "}") {
          lastCodeIndex = cursor;
          var lookahead = cursor + 1;
          while (lookahead < sourceText.length) {
            var lookaheadCh = sourceText.charAt(lookahead);
            if (lookaheadCh === " " || lookaheadCh === "\t" || lookaheadCh === "\r") {
              lookahead++;
              continue;
            }
            break;
          }
          // Isolate a minified module statement onto its own line so the
          // line-based rewriter below can normalize it. esbuild folds the
          // keyword onto the previous statement as `}}export{...}` (no `;`)
          // or `0;import"x"`. Dynamic `import(...)` / `import.meta` were
          // already rewritten before this pass, and the trailing
          // non-identifier guard keeps `}exports`, `;exporter`, etc. from
          // matching (a stray hit would only add a harmless newline anyway).
          var lookaheadKeyword = sourceText.slice(lookahead, lookahead + 6);
          if (
            (lookaheadKeyword === "import" || lookaheadKeyword === "export") &&
            !/[A-Za-z0-9_$]/.test(sourceText.charAt(lookahead + 6))
          ) {
            result += ch + "\n";
            cursor = lookahead - 1;
            continue;
          }
        }
        if (ch !== " " && ch !== "\t" && ch !== "\r" && ch !== "\n") {
          lastCodeIndex = cursor;
        }
        result += ch;
      }
      return result;
    };
    // Scan `text` outside strings, templates, and comments, reporting the
    // index of the first statement-terminating `;` (or -1). The multi-line
    // module-statement joiner below must not stop at a `;` that lives inside
    // a comment — authored barrels legitimately contain comments like
    // `// ... (LLP 0279 W3); removal at the ...` between export specifiers,
    // and treating that `;` as the statement end leaves a bare `export {`
    // in the CJS output, which Hermes rejects (ENG-22514).
    var indexOfStatementSemicolon = function(text) {
      var sourceText = String(text || "");
      var inSingle = false;
      var inDouble = false;
      var inLineComment = false;
      var inBlockComment = false;
      // Prior-token index for regex-vs-division decisions (ENG-22528).
      var lastCodeIndex = -1;
      for (var cursor = 0; cursor < sourceText.length; cursor++) {
        var ch = sourceText.charAt(cursor);
        var next = sourceText.charAt(cursor + 1);
        if (inLineComment) {
          if (ch === "\n") {
            inLineComment = false;
          }
          continue;
        }
        if (inBlockComment) {
          if (ch === "*" && next === "/") {
            cursor++;
            inBlockComment = false;
          }
          continue;
        }
        if (inSingle || inDouble) {
          if (ch === "\\") {
            cursor++;
            continue;
          }
          if (inSingle && ch === "'") {
            inSingle = false;
            lastCodeIndex = cursor;
          } else if (inDouble && ch === '"') {
            inDouble = false;
            lastCodeIndex = cursor;
          }
          continue;
        }
        if (ch === "/" && next === "/") {
          cursor++;
          inLineComment = true;
          continue;
        }
        if (ch === "/" && next === "*") {
          cursor++;
          inBlockComment = true;
          continue;
        }
        // Skip regex literals (ENG-22528): a `;` never terminates a
        // statement from inside /['";]/, and a quote in a regex must not
        // open a bogus string state.
        if (ch === "/") {
          var regexEnd = indexAfterRegexLiteral(sourceText, cursor, lastCodeIndex);
          if (regexEnd !== -1) {
            lastCodeIndex = regexEnd - 1;
            cursor = regexEnd - 1;
            continue;
          }
        }
        if (ch === "'") {
          inSingle = true;
          continue;
        }
        if (ch === '"') {
          inDouble = true;
          continue;
        }
        // Skip whole template literals, including ${...} interpolations
        // (ENG-22528): a `;` inside an interpolation (e.g. an arrow body)
        // is not a statement terminator.
        if (ch === "`") {
          var templateEnd = indexAfterTemplateLiteral(sourceText, cursor);
          lastCodeIndex = templateEnd - 1;
          cursor = templateEnd - 1;
          continue;
        }
        if (ch === ";") {
          return cursor;
        }
        if (ch !== " " && ch !== "\t" && ch !== "\r" && ch !== "\n") {
          lastCodeIndex = cursor;
        }
      }
      return -1;
    };
    // Remove `//` and `/* */` comments from a joined import/export statement
    // (string-aware) so the line-based statement regexes and the specifier
    // splitters in emitNamedBindings/emitExportBindings never see comment
    // text. Without this, a comment between specifiers makes the following
    // binding fail the identifier test and get silently dropped (ENG-22514:
    // `div`, `View`, and `getTagConfig` vanished from the `exact` barrel).
    var stripModuleStatementComments = function(text) {
      var sourceText = String(text || "");
      var result = "";
      var inSingle = false;
      var inDouble = false;
      var inLineComment = false;
      var inBlockComment = false;
      // Prior-token index for regex-vs-division decisions (ENG-22528).
      var lastCodeIndex = -1;
      for (var cursor = 0; cursor < sourceText.length; cursor++) {
        var ch = sourceText.charAt(cursor);
        var next = sourceText.charAt(cursor + 1);
        if (inLineComment) {
          if (ch === "\n") {
            inLineComment = false;
            result += ch;
          }
          continue;
        }
        if (inBlockComment) {
          if (ch === "*" && next === "/") {
            cursor++;
            inBlockComment = false;
          }
          continue;
        }
        if (inSingle || inDouble) {
          result += ch;
          if (ch === "\\") {
            result += next;
            cursor++;
            continue;
          }
          if (inSingle && ch === "'") {
            inSingle = false;
            lastCodeIndex = cursor;
          } else if (inDouble && ch === '"') {
            inDouble = false;
            lastCodeIndex = cursor;
          }
          continue;
        }
        if (ch === "/" && next === "/") {
          cursor++;
          inLineComment = true;
          continue;
        }
        if (ch === "/" && next === "*") {
          cursor++;
          inBlockComment = true;
          result += " ";
          continue;
        }
        // Preserve regex literals verbatim (ENG-22528): `//` inside a
        // character class (/[//]/) is not a comment, and a quote inside a
        // regex must not open a bogus string state.
        if (ch === "/") {
          var regexEnd = indexAfterRegexLiteral(sourceText, cursor, lastCodeIndex);
          if (regexEnd !== -1) {
            result += sourceText.slice(cursor, regexEnd);
            lastCodeIndex = regexEnd - 1;
            cursor = regexEnd - 1;
            continue;
          }
        }
        // Preserve whole template literals, including ${...} interpolations
        // (ENG-22528), so a backtick inside an interpolation cannot flip
        // the scanner's string/code state.
        if (ch === "`") {
          var templateEnd = indexAfterTemplateLiteral(sourceText, cursor);
          result += sourceText.slice(cursor, templateEnd);
          lastCodeIndex = templateEnd - 1;
          cursor = templateEnd - 1;
          continue;
        }
        if (ch === "'") {
          inSingle = true;
        } else if (ch === '"') {
          inDouble = true;
        } else if (ch !== " " && ch !== "\t" && ch !== "\r" && ch !== "\n") {
          lastCodeIndex = cursor;
        }
        result += ch;
      }
      return result;
    };
    var isCompleteStaticImportStatement = function(text) {
      var trimmedText = String(text || "").trim();
      return (
        /^\s*import\s+type\s+[\s\S]+?\s*from\s*(["'])([^'"]+)\1\s*;?\s*$/.test(trimmedText) ||
        /^\s*import\s*(["'])([^'"]+)\1\s*;?\s*$/.test(trimmedText) ||
        /^\s*import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/.test(trimmedText) ||
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([\s\S]*?)\}\s*from\s*(["'])([^'"]+)\3\s*;?\s*$/.test(trimmedText) ||
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\3\s*;?\s*$/.test(trimmedText) ||
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/.test(trimmedText) ||
        /^\s*import\s*\{([\s\S]*?)\}\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/.test(trimmedText)
      );
    };
    var splitLines = splitInlineModuleStatements(String(source)).split("\n");
    var importLines = [];
    var bodyLines = [];
    for (var lineIndex = 0; lineIndex < splitLines.length; lineIndex++) {
      var splitLine = splitLines[lineIndex];
      if (isCompleteStaticImportStatement(splitLine)) {
        importLines.push(splitLine);
      } else {
        bodyLines.push(splitLine);
      }
    }
    var lines = importLines.concat(bodyLines);
    var out = [];
    var importCounter = 0;
    var pendingVarExport = null;
    var pendingDefaultExport = null;
    var isIdent = /^[A-Za-z_$][\w$]*$/;
    var looksLikeCompleteModuleStatement = function(text) {
      var trimmedText = String(text || "").trim();
      return (
        isCompleteStaticImportStatement(trimmedText) ||
        /^\s*export\s*\*\s*from\s*(["'])([^'"]+)\1\s*;?\s*$/.test(trimmedText) ||
        /^\s*export\s*\{([\s\S]*?)\}\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/.test(trimmedText) ||
        /^\s*export\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/.test(trimmedText) ||
        /^\s*export\s*\{([^}]*)\}\s*;?\s*$/.test(trimmedText)
      );
    };
    var isExportName = function(value) {
      return value === "default" || isIdent.test(value);
    };
    var quote = function(value) {
      return JSON.stringify(value);
    };
    // Content-aware delimiter tracking for the line loop below lives in the
    // shared scanner-helper block (createDelimiterScanState /
    // delimiterScanInContent / scanDelimiterLine) — fixForOfScoping keeps a
    // file-wide scan state with the same mechanism (ENG-22536, ENG-22546).
    var emitNamedBindings = function(spec, modName) {
      var parts = spec ? spec.split(",") : [];
      for (var i = 0; i < parts.length; i++) {
        var item = parts[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var localName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isIdent.test(localName) || localName === "default") {
            continue;
          }
          if (sourceName === "default") {
            out.push("var " + localName + " = " + modName + " && " + modName + ".default;");
          } else {
            out.push("var " + localName + " = " + modName + "." + sourceName + ";");
          }
        } else if (isIdent.test(item)) {
          out.push("var " + item + " = " + modName + "." + item + ";");
        }
      }
    };
    var emitExportBindings = function(spec, sourceExpr, allowBareDefault, useLocals) {
      var entries = spec ? spec.split(",") : [];
      for (var i = 0; i < entries.length; i++) {
        var item = entries[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var exportName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isExportName(exportName)) {
            continue;
          }
          if (useLocals) {
            out.push("module.exports." + exportName + " = " + sourceName + ";");
          } else {
            out.push("module.exports." + exportName + " = " + sourceExpr + "." + sourceName + ";");
          }
          continue;
        }
        if (!allowBareDefault && item === "default") {
          continue;
        }
        if (isExportName(item)) {
          if (useLocals) {
            out.push("module.exports." + item + " = " + item + ";");
          } else {
            out.push("module.exports." + item + " = " + sourceExpr + "." + item + ";");
          }
        }
      }
    };
    var moduleScanState = createDelimiterScanState();
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();
      if (pendingDefaultExport) {
        // When the continuation line starts inside template text or a block
        // comment, leave it verbatim: the whole-source transformImportMeta
        // pass that follows transformEsmToCjs rewrites any code-context
        // occurrences with full lexical context (ENG-22536).
        var continuedDefault =
          line.indexOf("import.meta") !== -1 && !delimiterScanInContent(moduleScanState)
            ? transformImportMeta(line)
            : line;
        out.push(continuedDefault);
        scanDelimiterLine(continuedDefault, moduleScanState);
        if (
          moduleScanState.balance <= pendingDefaultExport.baseline &&
          !delimiterScanInContent(moduleScanState) &&
          /;\s*$/.test(trimmed)
        ) {
          pendingDefaultExport = null;
        }
        continue;
      }
      if (pendingVarExport) {
        var continued =
          line.indexOf("import.meta") !== -1 && !delimiterScanInContent(moduleScanState)
            ? transformImportMeta(line)
            : line;
        out.push(continued);
        scanDelimiterLine(continued, moduleScanState);
        var closesExportedIife = pendingVarExport.iife && /^\s*\}\s*\([^)]*\)\s*;\s*$/.test(trimmed);
        if (
          (moduleScanState.balance <= pendingVarExport.baseline &&
            !delimiterScanInContent(moduleScanState) &&
            /;\s*$/.test(trimmed)) ||
          closesExportedIife
        ) {
          out.push("module.exports." + pendingVarExport.name + " = " + pendingVarExport.name + ";");
          pendingVarExport = null;
        }
        continue;
      }
      if (delimiterScanInContent(moduleScanState)) {
        // This line starts inside multi-line template text or a block
        // comment that opened on an earlier line (ENG-22536). It is content,
        // not code — a line here that happens to look like an import/export
        // statement (e.g. a codegen template that renders module source)
        // must be emitted verbatim, not rewritten.
        scanDelimiterLine(line, moduleScanState);
        out.push(line);
        continue;
      }
      var statement = line;
      var isBlockExportDeclaration =
        /^\s*export\s+(default\s+)?(?:async\s+)?(?:function|class)\b/.test(trimmed);
      var isVarExportDeclaration = /^\s*export\s+(const|let|var)\b/.test(trimmed);
      var isDefaultExportExpression =
        /^\s*export\s+default\b/.test(trimmed) &&
        !/^\s*export\s+default\s+(?:async\s+)?(?:function|class)\b/.test(trimmed);
      var isModuleStatementHead =
        /^\s*(import|export)\b/.test(trimmed) &&
        !isBlockExportDeclaration &&
        !isVarExportDeclaration &&
        !isDefaultExportExpression;
      if (isModuleStatementHead && !looksLikeCompleteModuleStatement(statement)) {
        var firstSemicolon = indexOfStatementSemicolon(statement);
        if (firstSemicolon !== -1) {
          var trailingStatement = statement.slice(firstSemicolon + 1);
          statement = statement.slice(0, firstSemicolon + 1);
          if (trailingStatement.trim()) {
            // Vite commonly folds import declarations and follow-up interop
            // assignments onto the same physical line. Split the line here so
            // the import/export rewriter can normalize just the module syntax
            // and then feed the remaining JS back through the loop unchanged.
            lines.splice(i + 1, 0, trailingStatement);
          }
        } else {
          for (var j = i + 1; j < lines.length; j++) {
            statement = statement + "\n" + lines[j];
            if (indexOfStatementSemicolon(statement) !== -1) {
              i = j;
              break;
            }
          }
        }
      }
      if (isModuleStatementHead) {
        // Comments are legal anywhere inside import/export statements but the
        // statement matchers below are line-based regexes; strip them so a
        // comment between specifiers can neither break the match nor leak
        // into the emitted bindings.
        statement = stripModuleStatementComments(statement);
      }
      if (line.indexOf("import.meta") !== -1) {
        statement = transformImportMeta(statement);
      }
      var transformed = statement;
      trimmed = transformed.trim();
      // Advance the shared lexical scan over this statement (ENG-22536). The
      // rewrites the branches below apply are balance- and content-neutral
      // (keyword stripping, require()/module.exports emission), so scanning
      // the pre-rewrite statement keeps the state aligned with the output.
      var balanceBeforeStatement = moduleScanState.balance;
      scanDelimiterLine(transformed, moduleScanState);
      var m;

      if (!trimmed) {
        out.push("");
        continue;
      }

      m = trimmed.match(
        /^\s*(const|let|var)\s+([\s\S]+?)\s*=\s*await\s+globalThis\["import"\]\(([\s\S]+)\)\s*;?\s*$/
      );
      if (m) {
        out.push(m[1] + " " + m[2] + " = require(" + m[3] + ");");
        continue;
      }

      m = trimmed.match(/^\s*await\s+globalThis\["import"\]\(([\s\S]+)\)\s*;?\s*$/);
      if (m) {
        out.push("require(" + m[1] + ");");
        continue;
      }

      // Type-only imports/exports are erased at runtime in normal TS builds.
      // When the native fallback sees raw source that still contains them,
      // treat them as no-ops instead of handing unsupported syntax to Hermes.
      m = trimmed.match(/^\s*import\s+type\s+[\s\S]+?\s*from\s*(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        continue;
      }

      m = trimmed.match(/^\s*import\s*(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        out.push("require(" + quote(m[2]) + ");");
        continue;
      }

      m = trimmed.match(/^\s*import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push("var " + m[1] + " = require(" + quote(m[3]) + ");");
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([\s\S]*?)\}\s*from\s*(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var namedImport = "__exmod" + (importCounter++);
        out.push("var " + namedImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            namedImport +
            " && " +
            namedImport +
            ".__esModule ? " +
            namedImport +
            ".default : " +
            namedImport +
            ";"
        );
        emitNamedBindings(m[2], namedImport);
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var nsImport = "__exmod" + (importCounter++);
        out.push("var " + nsImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            nsImport +
            " && " +
            nsImport +
            ".__esModule ? " +
            nsImport +
            ".default : " +
            nsImport +
            ";"
        );
        out.push("var " + m[2] + " = " + nsImport + ";");
        continue;
      }

      m = trimmed.match(/^\s*import\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        // Same __esModule-conditional interop as the `import X, {a}` branch
        // above: the old `require(m).default || require(m)` bound the whole
        // namespace whenever the default export was falsy (0/''/false/null),
        // so the two default-import forms disagreed (ENG-23481 #9). Kept to
        // one emitted line so the transform stays line-preserving here.
        out.push(
          "var " +
            m[1] +
            " = (function(__exm){ return __exm && __exm.__esModule ? __exm.default : __exm; })(require(" +
            quote(m[3]) +
            "));"
        );
        continue;
      }

      m = trimmed.match(/^\s*import\s*\{([\s\S]*?)\}\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var named = "__exmod" + (importCounter++);
        out.push("var " + named + " = require(" + quote(m[3]) + ");");
        emitNamedBindings(m[1], named);
        continue;
      }

      m = trimmed.match(/^\s*export\s*\*\s*from\s*(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[2]) + ");");
        out.push("for (var __exk in " + exportFrom + ") {");
        out.push("  if (Object.prototype.hasOwnProperty.call(" + exportFrom + ", __exk)) {");
        out.push("    module.exports[__exk] = " + exportFrom + "[__exk];");
        out.push("  }");
        out.push("}");
        continue;
      }

      m = trimmed.match(/^\s*export\s+type\s*\{[\s\S]*?\}\s*from\s*(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        continue;
      }

      m = trimmed.match(/^\s*export\s*\{([\s\S]*?)\}\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[3]) + ");");
        emitExportBindings(m[1], exportFrom, true, false);
        continue;
      }

      m = trimmed.match(
        /^\s*export\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(["'])([^'"]+)\2\s*;?\s*$/
      );
      if (m) {
        var nsExport = "__exmod" + (importCounter++);
        out.push("var " + nsExport + " = require(" + quote(m[3]) + ");");
        out.push("module.exports." + m[1] + " = " + nsExport + ";");
        continue;
      }

      m = transformed.match(
        /^(\s*)export\s+default\s+async\s+function\s+([A-Za-z_$][\w$]*)([\s\S]*)$/
      );
      if (m) {
        out.push(
          m[1] +
            "const " +
            m[2] +
            " = module.exports.default = async function " +
            m[2] +
            m[3]
        );
        continue;
      }

      m = transformed.match(
        /^(\s*)export\s+default\s+function\s+([A-Za-z_$][\w$]*)([\s\S]*)$/
      );
      if (m) {
        out.push(
          m[1] +
            "const " +
            m[2] +
            " = module.exports.default = function " +
            m[2] +
            m[3]
        );
        continue;
      }

      m = transformed.match(/^(\s*)export\s+default\s+class\s+([A-Za-z_$][\w$]*)([\s\S]*)$/);
      if (m) {
        out.push(
          m[1] +
            "const " +
            m[2] +
            " = module.exports.default = class " +
            m[2] +
            m[3]
        );
        continue;
      }

      m = transformed.match(/^(\s*)export\s+default\s+async\s+function([\s\S]*)$/);
      if (m) {
        out.push(m[1] + "module.exports.default = async function" + m[2]);
        continue;
      }

      m = transformed.match(/^(\s*)export\s+default\s+function([\s\S]*)$/);
      if (m) {
        out.push(m[1] + "module.exports.default = function" + m[2]);
        continue;
      }

      m = transformed.match(/^(\s*)export\s+default\s+class([\s\S]*)$/);
      if (m) {
        out.push(m[1] + "module.exports.default = class" + m[2]);
        continue;
      }

      m = transformed.match(/^(\s*)export\s+default\s+([\s\S]*)$/);
      if (m) {
        var defaultDeclaration = m[1] + "module.exports.default = " + m[2];
        out.push(defaultDeclaration);
        if (
          !/;\s*$/.test(trimmed) ||
          moduleScanState.balance > balanceBeforeStatement ||
          delimiterScanInContent(moduleScanState)
        ) {
          pendingDefaultExport = {
            baseline: balanceBeforeStatement
          };
        }
        continue;
      }

      m = transformed.match(/^(\s*)export\s+async\s+function\s+([A-Za-z_$][\w$]*)([\s\S]*)$/);
      if (m) {
        out.push(
          m[1] +
            "const " +
            m[2] +
            " = module.exports." +
            m[2] +
            " = async function " +
            m[2] +
            m[3]
        );
        continue;
      }

      m = transformed.match(/^(\s*)export\s+function\s+([A-Za-z_$][\w$]*)([\s\S]*)$/);
      if (m) {
        out.push(
          m[1] +
            "const " +
            m[2] +
            " = module.exports." +
            m[2] +
            " = function " +
            m[2] +
            m[3]
        );
        continue;
      }

      m = transformed.match(/^(\s*)export\s+class\s+([A-Za-z_$][\w$]*)([\s\S]*)$/);
      if (m) {
        out.push(
          m[1] +
            "const " +
            m[2] +
            " = module.exports." +
            m[2] +
            " = class " +
            m[2] +
            m[3]
        );
        continue;
      }

      m = trimmed.match(/^\s*export\s+default\s+(.+)\s*$/);
      if (m) {
        out.push("module.exports.default = " + m[1] + ";");
        continue;
      }

      m = transformed.match(/^(\s*)export\s+(const|let|var)\s+([A-Za-z_$][\w$]*)([\s\S]*)$/);
      if (m) {
        var declaration = transformed.replace(/\bexport\s+/, "");
        out.push(declaration);
        if (
          /;\s*$/.test(trimmed) &&
          moduleScanState.balance <= balanceBeforeStatement &&
          !delimiterScanInContent(moduleScanState)
        ) {
          out.push("module.exports." + m[3] + " = " + m[3] + ";");
        } else {
          pendingVarExport = {
            name: m[3],
            baseline: balanceBeforeStatement,
            iife: new RegExp("^\\s*(?:var|let|const)\\s+" + m[3] + "\\s*=\\s*function\\b").test(declaration)
          };
        }
        continue;
      }

      m = trimmed.match(/^\s*export\s+type\s*\{[^}]*\}\s*;?\s*$/);
      if (m) {
        continue;
      }

      m = trimmed.match(/^\s*export\s*\{([^}]*)\}\s*;?\s*$/);
      if (m) {
        emitExportBindings(m[1], null, false, true);
        continue;
      }

      out.push(transformed);
    }
    return out.join("\n");
  }
  // @ref LLP 0013#policy — the import-graph gate (Policy surface 3), applied at
  // every package-facing require entry point (localRequire, globalThis.require,
  // dynamic import()). The native __exactCheckImport re-derives the requesting
  // principal from the executing frame — never trusting a JS-passed id — so the
  // gate fires even for dynamic import() and globalThis.require, which carry no
  // module `parent`, and cannot be bypassed by a forged parent. Inert for the
  // root and runtime principals and for packages the policy does not restrict;
  // the host logs (audit) or denies (enforce). Placed at the entry points (not
  // deep inside load()) so the loader's own internal fan-out — e.g. mapping
  // 'dns/promises' to an internal load('dns') — is not re-gated under the
  // requesting package's principal against a different specifier. (ENG-22618/ENG-22629)
  //
  // Deliberately NOT memoized here (and not moved after load()'s module-cache
  // hit): the true requesting principal is frame-derived on the native side and
  // is not knowable in JS — a (requesterHint, specifier) memo would let package
  // Q skip the check by calling a require closure it obtained from an
  // already-allowed package P, and a post-cache-hit gate would let any package
  // reach any module some other principal already loaded. The repeated-require
  // fast path lives in the host instead: CapabilityManager memoizes ALLOWED
  // (principal, specifier) decisions keyed by the frame-derived principal, so
  // the steady state is one native call + a hash hit, while denials always run
  // the full path and keep their audit entries. (ENG-22644)
  function checkImportGate(specifier, requesterHint) {
    if (!__privCheckImport || typeof specifier !== 'string') return;
    // On the frame-attribution engine the native check re-derives the requesting
    // principal from the executing frame and IGNORES this hint. On an unpatched
    // engine (no EXACT_HAVE_FRAME_ATTRIBUTION) it falls back to the passed id, so
    // pass the requester's package id where the call site knows it (static
    // require has the enclosing module) — otherwise the gate would go inert on
    // those builds and a restricted package's static require would be allowed as
    // root. Global entry points (globalThis.require / dynamic import) have no
    // module context and pass 0 there — but those paths were already ungated on
    // unpatched builds, so this is no regression. (ENG-22618 review)
    var hint = typeof requesterHint === 'number' ? requesterHint : 0;
    if (!__privCheckImport(hint, specifier)) {
      throw new Error(
        "Import denied: '" + specifier + "' is not permitted for this package (LLP 0013 import policy)");
    }
  }
  // Builtin module identity: the native resolver emits one registry record per
  // alias (`fs`, `node:fs`, `bun:fs`, `util`/`sys`, ...) with `id` set to the
  // raw specifier, so caching by `id` re-evaluated each builtin once per alias
  // and forked its state — distinct EventEmitter classes, fs watch registries,
  // http globalAgent — and paid double eval time/memory. Canonicalize builtin
  // cache keys so every alias of one builtin shares a single instance. Aliases
  // cannot be merged by NAME — `exact:http` vs `http`, and `node:url` vs `url`,
  // resolve to DIFFERENT source modules — so dedupe on the resolved source text,
  // which is byte-identical across an alias group and distinct across modules.
  // Re-export aliases (`path/posix` -> `require('path').posix`) get their own
  // key but already share identity through the re-exported value. (ENG-22981)
  var __builtinCanonicalByAlias = Object.create(null);
  var __builtinCanonicalBySource = Object.create(null);
  function builtinCacheKeyFor(id, source) {
    var memo = __builtinCanonicalByAlias[id];
    if (typeof memo === 'string') {
      return memo;
    }
    var src = typeof source === 'string' ? source : '';
    var canonical = __builtinCanonicalBySource[src];
    if (typeof canonical !== 'string') {
      // First alias seen for this source defines the shared cache key.
      canonical = id;
      __builtinCanonicalBySource[src] = canonical;
    }
    __builtinCanonicalByAlias[id] = canonical;
    return canonical;
  }
  function load(specifier, referrer, parent) {
    __exactPinProcessStreams();

    // @ref LLP 0013#mechanism-3 — per-package chunk requires (`__ibexpkg__*`)
    // and the shared bundler runtime chunk (`rolldown-runtime.js`, emitted for
    // ESM/interop apps) live in the bundle cache dir, but the entry's
    // `__dirname` is mapped to the source dir; resolve these specifiers
    // absolutely against the chunk dir so sibling chunks are found while the
    // entry keeps source-relative __dirname. Without the runtime-chunk redirect,
    // an ESM app would fail to resolve `./rolldown-runtime.js` once chunking is
    // on (which enforce/audit now does by default — ENG-22681/ENG-22624).
    if (typeof specifier === 'string' && g.__exactChunkDir &&
        (specifier.indexOf('__ibexpkg__') !== -1 ||
         specifier === './rolldown-runtime.js')) {
      var __ci = specifier.lastIndexOf('/');
      var __cbase = __ci === -1 ? specifier : specifier.slice(__ci + 1);
      // Only bundler-emitted chunk basenames resolve against the cache dir. Reject
      // anything with a backslash (a Windows path separator), a `..` segment, or a
      // NUL so the basename cannot escape __exactChunkDir. @ref LLP 0013#mechanism-3
      var __isChunk = __cbase.indexOf('__ibexpkg__') === 0 ||
          specifier === './rolldown-runtime.js';
      if (__isChunk &&
          __cbase.indexOf('\\') === -1 &&
          __cbase.indexOf('..') === -1 &&
          __cbase.indexOf('\0') === -1) {
        specifier = g.__exactChunkDir + '/' + __cbase;
      }
    }

    // Lazy-load triggers: ensure non-essential bootstrap blocks are loaded
    // when their corresponding modules are first required.
    if (typeof __exactEnsureStreamEnhance === 'function') {
      if (specifier === 'stream' || specifier === 'stream/web' ||
          specifier === 'node:stream' || specifier === 'node:stream/web') {
        __exactEnsureStreamEnhance();
      }
    }
    if (typeof __exactEnsureWebCrypto === 'function' && !isWindowsRuntime()) {
      if (specifier === 'crypto' || specifier === 'node:crypto') {
        __exactEnsureWebCrypto();
      }
    }
    if (typeof __exactEnsureDns === 'function') {
      if (specifier === 'dns' || specifier === 'node:dns' ||
          specifier === 'dns/promises' || specifier === 'node:dns/promises') {
        __exactEnsureDns();
      }
    }
    if (typeof __exactEnsureFs === 'function') {
      if (specifier === 'fs' || specifier === 'node:fs' ||
          specifier === 'fs/promises' || specifier === 'node:fs/promises' ||
          specifier === 'path' || specifier === 'node:path' ||
          specifier === 'path/posix' || specifier === 'node:path/posix' ||
          specifier === 'path/win32' || specifier === 'node:path/win32') {
        __exactEnsureFs();
      }
    }
    if (typeof __exactEnsureChildProcess === 'function') {
      if (specifier === 'child_process' || specifier === 'node:child_process') {
        __exactEnsureChildProcess();
      }
    }
    if (typeof __exactEnsureNet === 'function') {
      if (specifier === 'net' || specifier === 'node:net' ||
          specifier === 'tls' || specifier === 'node:tls' ||
          specifier === 'dgram' || specifier === 'node:dgram') {
        __exactEnsureNet();
      }
    }
    if (typeof __exactEnsureSqlite === 'function') {
      if (specifier === 'exact:sqlite' || specifier === 'bun:sqlite' ||
          specifier === 'node:sqlite' || specifier === 'sqlite' ||
          specifier === 'better-sqlite3') {
        __exactEnsureSqlite();
      }
    }
    var resolvedSpecifier = stripViteImportQuery(specifier);
    var normalized = normalizeSpecifier(resolvedSpecifier);
    if (normalized === 'fs/promises') {
      if (cache[normalized] && cache[normalized].loaded) {
        return cache[normalized].exports;
      }
      var fsModule = cache.fs || cache['node:fs'] || cache['fs/promises'] || cache['node:fs/promises'];
      var fsExports = fsModule && fsModule.exports ? fsModule.exports : fsModule;
      if (!fsExports || !fsExports.promises) {
        fsExports = load('fs', referrer, parent);
      }
      if (fsExports && fsExports.promises) {
        var cachedFsPromises = {
          exports: fsExports.promises,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
        cache[normalized] = cache[normalized] || cachedFsPromises;
        cache[normalized].exports = cachedFsPromises.exports;
        cache[normalized].loaded = true;
        return cache[normalized].exports;
      }
      return {};
    }
    if (typeof __exactEnsureHttp === 'function') {
      if (specifier === 'http' || specifier === 'node:http' ||
          specifier === 'https' || specifier === 'node:https' ||
          specifier === 'http2' || specifier === 'node:http2') {
        __exactEnsureHttp();
      }
    }
    normalized = normalizeSpecifier(resolvedSpecifier);
    if (internalModules.hasOwnProperty(normalized)) {
      if (!cache[normalized]) {
        cache[normalized] = { exports: internalModules[normalized], loaded: true };
      }
      return cache[normalized].exports;
    }
    const json = __exactModuleResolve(resolvedSpecifier, referrer || "");
    if (!json) {
      throw new Error("Module not found: " + specifier);
    }
    let record;
    try {
      record = JSON.parse(json);
    } catch (err) {
      throw new Error("Module resolve failed: " + err.message);
    }
    if (record.error) {
      throw new Error(record.error);
    }
    // Import policy (Policy surface 3) for BARE specifiers is enforced at the
    // package-facing entry points via checkImportGate(), not here: load() is also
    // the loader's own internal module-resolution primitive (alias fan-out,
    // builtin plumbing), whose calls must not be attributed to the requesting
    // package against a rewritten specifier. (ENG-22618/ENG-22629)
    //
    // Relative/absolute specifiers, however, can only be classified after
    // resolution: `../sibling/index.js` resolves to a DIFFERENT package that the
    // raw-specifier entry gate can't see, so a package with a restricted
    // `packages` axis could otherwise reach a sibling package by path traversal.
    // Gate the resolved target's package name when it differs from the requester's
    // (intra-package relative imports are not cross-package edges and are allowed).
    // (ENG-22637 review)
    if (__privCheckImport && isPathSpecifier(specifier)) {
      var __targetPkg = packageNameForRecord(record, parent);
      if (__targetPkg) {
        var __reqId = (parent && typeof parent.__exactPackageId === 'number')
          ? parent.__exactPackageId : null;
        var __tgtId = packagePrincipalFor(record, parent);
        if (__reqId === null || __reqId !== __tgtId) {
          checkImportGate(__targetPkg, __reqId === null ? undefined : __reqId);
        }
      }
    }
    const id = record.id || resolvedSpecifier;
    // Builtins share one instance across all their aliases; user modules stay
    // keyed by their (path-based) id. (ENG-22981)
    const cacheKey = record.kind === 'builtin'
      ? builtinCacheKeyFor(id, record.source)
      : id;
    var moduleId = idToModuleId(id);
    if (cache[cacheKey]) {
      return cache[cacheKey].exports;
    }
    const kind = record.kind || "cjs";
    const source = normalizeHashbang(record.source || "");
    var filename = record.path || id;
    // For the entry module, use the original source path so that
    // __dirname/__filename and require.resolve work relative to
    // the source dir, not the bundle cache dir. The entry is the FIRST
    // parentless non-builtin load (the Rust runner issues `require(<bundle>)`
    // with no parent; builtins loaded during bootstrap are skipped above or
    // carry kind 'builtin'). The old detector keyed on a '/Caches/' substring,
    // which only exists in the macOS cache dir (~/Library/Caches/Ibex) — on
    // Linux (~/.cache/ibex) and Windows (%LOCALAPPDATA%\ibex) it never fired
    // and the entry's __dirname pointed into the bundle cache (ENG-23481 #4).
    // Instead match the bundle_output_path shape from src/bin/ibex/runtime.rs
    // (`<cache>/<key>.bundle.{js,mjs}` flat, `<cache>/<key>/bundle.{js,mjs}`
    // per-package-chunked), which is platform-independent. The flag is
    // consumed on the first candidate load either way so a later parentless
    // require of a user file that happens to be named `*.bundle.js` cannot
    // steal the remap.
    if (g.__exactEntryFile && !g.__exactEntryFileConsumed &&
        !parent && record.kind !== 'builtin') {
      g.__exactEntryFileConsumed = true;
      if (/(?:^|[\/.])bundle\.m?js$/.test(filename.replace(/\\/g, '/'))) {
        filename = g.__exactEntryFile;
      }
    }
    const modulePath = filename.indexOf('/') === -1 ? filename : dirname(filename);
    // Compute node_modules search paths for this module
    var modulePaths = [];
    var pathParts = modulePath.split('/');
    for (var pi = pathParts.length - 1; pi >= 0; pi--) {
      if (pathParts[pi] === 'node_modules') continue;
      modulePaths.push(pathParts.slice(0, pi + 1).join('/') + '/node_modules');
    }
    const module = {
      id: id,
      __exactId: moduleId,
      __exactPackageName: packageNameForRecord(record, parent),
      __exactPackageRoot: packageRootForRecord(record),
      __exactPackageId: packagePrincipalFor(record, parent),
      __exactCompartment: compartmentForRecord(record, parent),
      filename: filename,
      path: modulePath,
      exports: {},
      loaded: false,
      parent: parent || null,
      children: [],
      paths: modulePaths,
    };
    cache[cacheKey] = module;
    if (!parent && !mainModule) {
      mainModule = module;
    }
    addChild(parent, module);

    module.require = function(next, options) {
      grantCapabilities(next, options, module.__exactId);
      return localRequire(next);
    };

    if (kind === "json") {
      try {
        module.exports = JSON.parse(source || "null");
      } catch (err) {
        delete cache[cacheKey];
        throw err;
      }
      module.loaded = true;
      return module.exports;
    }
    const dir = dirname(filename);
    const looksLikeModuleSyntax = function(text) {
      return /\n?\s*(?:import|export)\b/m.test(text || "");
    };
    const isAwaitSyntaxFailure = function(err) {
      if (!err || (err.name !== "SyntaxError" && err.name !== "ReferenceError")) {
        return false;
      }
      var message = String(err.message || "");
      // Hermes reports top-level await failures in a couple of different ways
      // depending on which parser path we hit. Treat them all as the same
      // recoverable signal instead of trying to predict top-level await from
      // the raw source text with a regex.
      if (message.indexOf("Property 'await'") !== -1) {
        return true;
      }
      if (message.indexOf("await is not defined") !== -1) {
        return true;
      }
      if (message.indexOf("await") === -1) {
        return false;
      }
      return (
        message.indexOf("async functions") !== -1 ||
        message.indexOf("top level bodies of modules") !== -1 ||
        message.indexOf("Unexpected reserved word") !== -1 ||
        message.indexOf("Unexpected identifier 'await'") !== -1 ||
        message.indexOf("Cannot use keyword 'await'") !== -1
      );
    };
    const wrapAsyncModule = function(text) {
      return "(async function() {\n" + String(text || "") + "\n})();";
    };
    const isOwnBodyAwaitReferenceError = function(err) {
      // An invocation-time "await is not defined" ReferenceError means THIS
      // module's own top-level code used a sloppy-mode-parsable await form
      // (e.g. `await (expr)` / `await.x`, typically minified top-level await),
      // so the body genuinely needs the async-wrapped fallback. A propagated
      // error from a nested require() carries the 'While evaluating module'
      // annotation added by load()'s catch and must NOT retry this body.
      if (!err || err.name !== "ReferenceError") {
        return false;
      }
      var message = String(err.message || "");
      if (message.indexOf('While evaluating module "') !== -1) {
        return false;
      }
      return message.indexOf("await is not defined") !== -1 ||
        message.indexOf("Property 'await'") !== -1;
    };
    var localRequire = function(next) {
      // Pass the enclosing module's principal as the fallback hint so the gate
      // still enforces on non-frame-attribution builds. (ENG-22618 review)
      checkImportGate(next, module && module.__exactPackageId);
      var internal = loadInternal(next);
      if (internal) return internal;
      var exports = load(next, filename, module);
      // Skip interop for ESM-shimmed modules — the shim's generated
      // import bindings already handle default/named/namespace access.
      if (exports && exports.__esmShimmed) {
        return exports;
      }
      // ESM/CJS interop: when a bundled ESM module is loaded via require(),
      // rolldown wraps it with __esModule:true. Return .default so that
      // require('pkg') returns the default export directly, with named
      // exports merged onto it so destructuring still works.
      if (exports && exports.__esModule && exports.default !== undefined) {
        var def = exports.default;
        if (def && (typeof def === "function" || typeof def === "object")) {
          var keys = Object.keys(exports);
          for (var ki = 0; ki < keys.length; ki++) {
            var k = keys[ki];
            if (k !== "default" && k !== "__esModule" && !(k in def)) {
              try { def[k] = exports[k]; } catch (e) {}
            }
          }
        }
        return def;
      }
      return exports;
    };
    localRequire.resolve = function(specifier) {
      return __exactResolvePath(specifier, filename || "");
    };
    localRequire.resolve.paths = function(specifier) {
      return null;
    };
    localRequire.cache = cache;
    localRequire.main = mainModule;
    const restoreModuleId = function(previousId) {
      if (__privSetActiveModuleId) {
        __privSetActiveModuleId(previousId || 0);
      }
    };
    const previousModuleId = __privSetActiveModuleId
      ? __privSetActiveModuleId(module.__exactId)
      : 0;
    const previousNodeFilename = g.__filename;
    const previousNodeDirname = g.__dirname;
    const moduleDynamicImport = function(specifier, options) {
      return importImpl(specifier, options, filename, module);
    };
    try {
      const splitDirectivePrologue = function(text) {
        var sourceText = String(text || "");
        var length = sourceText.length;
        var cursor = 0;
        var prologueEnd = 0;

        function skipWhitespaceAndComments(index) {
          var current = index;
          while (current < length) {
            var ch = sourceText.charAt(current);
            if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === '\f') {
              current++;
              continue;
            }
            if (ch === '/' && sourceText.charAt(current + 1) === '/') {
              current += 2;
              while (current < length && sourceText.charAt(current) !== '\n') current++;
              continue;
            }
            if (ch === '/' && sourceText.charAt(current + 1) === '*') {
              current += 2;
              while (current < length) {
                if (sourceText.charAt(current) === '*' && sourceText.charAt(current + 1) === '/') {
                  current += 2;
                  break;
                }
                current++;
              }
              continue;
            }
            break;
          }
          return current;
        }

        cursor = skipWhitespaceAndComments(0);
        while (cursor < length) {
          var quote = sourceText.charAt(cursor);
          if (quote !== '"' && quote !== "'") break;
          var scan = cursor + 1;
          while (scan < length) {
            var token = sourceText.charAt(scan);
            if (token === '\\') {
              scan += 2;
              continue;
            }
            if (token === quote) break;
            scan++;
          }
          if (scan >= length || sourceText.charAt(scan) !== quote) break;
          scan++;
          while (scan < length) {
            var trailing = sourceText.charAt(scan);
            if (trailing === ' ' || trailing === '\t' || trailing === '\r') {
              scan++;
              continue;
            }
            if (trailing === ';') {
              scan++;
            }
            break;
          }
          cursor = skipWhitespaceAndComments(scan);
          prologueEnd = cursor;
        }

        if (prologueEnd === 0) {
          return {
            prologue: '',
            body: sourceText
          };
        }

        return {
          prologue: sourceText.slice(0, prologueEnd),
          body: sourceText.slice(prologueEnd)
        };
      };
      // The preamble is injected into EVERY loader-served module body: the
      // shim must install per compartment global, not once per runtime —
      // under LLP 0013 Phase 3 a package's bare `globalThis` resolves to its
      // compartment global, so both the `__exactCompatEval` guard and the
      // `globalThis.eval` wrap have to run inside the module's own compiled
      // code (the loader's scope only sees the root global). It is emitted as
      // a SINGLE line joined directly onto the body's first line so it adds
      // zero lines: the old 38-line preamble sat under a sourceURL pointing
      // at the original file, shifting every reported stack-trace line number
      // ~39 lines below the real source line (ENG-23481 #11).
      const injectEvalShimPreamble = function(text) {
        var split = splitDirectivePrologue(text);
        return split.prologue + evalShimPreamble + split.body;
      };
      const evalShimPreamble =
        "globalThis.__exactImportMeta = globalThis.__exactImportMeta || {}; " +
        "if (typeof globalThis.__exactCompatEval !== 'function') { " +
        "(function() { " +
        "var __exactNativeEval = globalThis.eval; " +
        "function __exactMaybeHandleNativesSyntax(source) { " +
        "if (typeof source !== 'string') { return null; } " +
        "var trimmed = source.trim(); " +
        "if (trimmed.charAt(0) !== '%' || trimmed.charAt(trimmed.length - 1) !== ')') { return null; } " +
        "var openParen = trimmed.indexOf('('); " +
        "if (openParen <= 1) { return null; } " +
        "switch (trimmed.slice(1, openParen).trim()) { " +
        "case 'PrepareFunctionForOptimization': " +
        "case 'OptimizeFunctionOnNextCall': " +
        "return { handled: true, value: undefined }; " +
        "default: " +
        "return null; " +
        "} " +
        "} " +
        "var __exactCompatEval = function evalCompat(source) { " +
        "var handled = __exactMaybeHandleNativesSyntax(source); " +
        "if (handled && handled.handled) { return handled.value; } " +
        "return __exactNativeEval(source); " +
        "}; " +
        "__exactCompatEval.__exactWrappedForNativesSyntax = true; " +
        "globalThis.__exactCompatEval = __exactCompatEval; " +
        "if (typeof globalThis.eval === 'function' && !globalThis.eval.__exactWrappedForNativesSyntax) { " +
        "globalThis.eval = __exactCompatEval; " +
        "} " +
        "})(); " +
        "} ";
      const transformedSource =
        transformDynamicImport(transformImportMeta(applyRolldownCjsDirnameBindings(fixForOfScoping(fixEsmCjsInterop(source || "")), filename)));
      const directSource =
        injectEvalShimPreamble(transformedSource) +
        "\n//# sourceURL=" + filename;
      const runFallbackModule = function(reason) {
        let runtimeSource = transformDynamicImport(
          transformImportMeta(
            applyRolldownCjsDirnameBindings(
              fixForOfScoping(transformEsmToCjs(transformedSource)),
              filename
            )
          )
        );
        runtimeSource = injectEvalShimPreamble(runtimeSource) +
          "\n//# sourceURL=" + filename;
        let wrappedRuntimeForAwait = false;
        const compileFallbackSource = function(sourceText) {
          return compileModuleBody(module.__exactPackageId, module.__exactCompartment, sourceText);
        };
        const invokeFallbackSource = function(fallbackFn) {
          g.__filename = filename;
          g.__dirname = dir;
          fallbackFn(localRequire, module, module.exports, filename, dir, moduleDynamicImport);
        };
        if (reason === "await-syntax") {
          runtimeSource = wrapAsyncModule(runtimeSource);
          wrappedRuntimeForAwait = true;
        }
        let fallbackFn;
        try {
          g.__exactDebugModuleSource = runtimeSource;
          // Try the transformed fallback in script form unless we already know
          // it needs async wrapping. Construction-time await syntax is still
          // recoverable here because the module body has not run yet.
          fallbackFn = compileFallbackSource(runtimeSource);
        } catch (fallbackErr) {
          if (wrappedRuntimeForAwait || !isAwaitSyntaxFailure(fallbackErr)) {
            throw fallbackErr;
          }
          runtimeSource = wrapAsyncModule(runtimeSource);
          wrappedRuntimeForAwait = true;
          g.__exactDebugModuleSource = runtimeSource;
          fallbackFn = compileFallbackSource(runtimeSource);
        }
        try {
          invokeFallbackSource(fallbackFn);
        } catch (invokeErr) {
          // Invocation-time errors must not re-run the body — except the
          // narrow own-body top-level-await ReferenceError, where the async
          // retry gets a FRESH exports object rebound into the cache entry so
          // it cannot trip over non-configurable getters the first pass
          // defined. The prefix before the failing await runs twice; that
          // double execution is a deliberate trade for keeping minified
          // top-level-await modules loadable. (ENG-22811)
          if (wrappedRuntimeForAwait || !isOwnBodyAwaitReferenceError(invokeErr)) {
            throw invokeErr;
          }
          runtimeSource = wrapAsyncModule(runtimeSource);
          wrappedRuntimeForAwait = true;
          g.__exactDebugModuleSource = runtimeSource;
          module.exports = {};
          invokeFallbackSource(compileFallbackSource(runtimeSource));
        }
        pushDebugModuleSource({
          id: id,
          filename: filename,
          source: runtimeSource.slice(0, 2000),
          fallback: true,
          fallbackReason: reason,
          asyncWrapped: wrappedRuntimeForAwait
        });
        g.__exactDebugModuleSource = runtimeSource;
        if (module.exports && typeof module.exports === "object") {
          module.exports.__esModule = true;
          Object.defineProperty(module.exports, '__esmShimmed', { value: true });
        }
      };
      if (kind === "esm" && looksLikeModuleSyntax(transformedSource)) {
        runFallbackModule("esm-syntax");
      } else {
        pushDebugModuleSource({ id: id, filename: filename, source: directSource.slice(0, 2000) });
        g.__exactDebugModuleSource = directSource;
        let directFn;
        try {
          directFn = compileModuleBody(module.__exactPackageId, module.__exactCompartment, directSource);
        } catch (err) {
          const needsAsyncFallback = isAwaitSyntaxFailure(err);
          const shouldFallback = (
            kind === "esm" ||
            looksLikeModuleSyntax(directSource) ||
            directSource.indexOf('await globalThis["import"](') !== -1 ||
            directSource.indexOf('await __exactDynamicImport(') !== -1 ||
            needsAsyncFallback
          );
          const canFallback = shouldFallback &&
            err &&
            (err.name === "SyntaxError" || needsAsyncFallback) &&
            directSource.length > 0;
          if (!canFallback) {
            throw err;
          }
          runFallbackModule(needsAsyncFallback ? "await-syntax" : "direct-syntax-error");
          directFn = null;
        }
        if (directFn) {
          // Only construction-time syntax failures are safe to retry through
          // the transformed fallback. Once invocation starts, the module body
          // may have mutated exports or globals, so nested errors (including
          // propagated nested SyntaxErrors) must bubble instead of re-running
          // a partially-executed body against the same exports.
          // @ref LLP 0006#degrade-diagnostics-never-the-caller
          g.__filename = filename;
          g.__dirname = dir;
          try {
            directFn(localRequire, module, module.exports, filename, dir, moduleDynamicImport);
          } catch (err) {
            if (!isOwnBodyAwaitReferenceError(err)) {
              throw err;
            }
            // Own-body top-level await parsed as a sloppy-mode identifier and
            // only failed at invocation. Retry through the async-wrapped
            // fallback with a FRESH exports object rebound into the cache
            // entry (the cache holds `module`, so callers see the new object)
            // so the re-run cannot hit "property is not configurable" from
            // getters the first pass defined. The prefix before the failing
            // await deliberately runs twice. (ENG-22811)
            module.exports = {};
            runFallbackModule("await-syntax");
          }
        }
      }
    } catch (err) {
      delete cache[cacheKey];
      var moduleErrorPrefix = 'While evaluating module "' + id + '": ';
      if (err && (typeof err === 'object' || typeof err === 'function')) {
        // Annotate and rethrow the original error so its stack, cause, and
        // custom properties survive; rebuilding a bare Error here flattened
        // every module failure. @ref LLP 0006#degrade-diagnostics-never-the-caller
        try {
          if (typeof err.message === 'string') {
            err.message = moduleErrorPrefix + err.message;
          }
          if (typeof err.stack === 'string' && err.stack) {
            err.stack = moduleErrorPrefix + err.stack;
          }
        } catch (_annotationFailure) {
          // Frozen/sealed error: rethrow unannotated rather than flatten.
        }
        throw err;
      }
      throw new Error(moduleErrorPrefix + String(err));
    } finally {
      if (typeof previousNodeFilename === "undefined") {
        delete g.__filename;
      } else {
        g.__filename = previousNodeFilename;
      }
      if (typeof previousNodeDirname === "undefined") {
        delete g.__dirname;
      } else {
        g.__dirname = previousNodeDirname;
      }
      restoreModuleId(previousModuleId);
    }
    module.loaded = true;
    return module.exports;
  }
  // Convert a module specifier or id to a numeric module identifier used
  // by runtime capability checks.
  var idToModuleId = function(specifier) {
    var id = typeof specifier === "string" ? specifier : String(specifier || "");
    var moduleId = 0;
    for (var i = 0; i < id.length; i++) {
      moduleId = ((moduleId << 5) - moduleId) + id.charCodeAt(i);
      moduleId = moduleId & moduleId;
    }
    return moduleId < 0 ? -moduleId : moduleId;
  };

  // Helper to grant capabilities from options parameter
  var grantCapabilities = function(specifier, options, moduleId) {
    if (!options || typeof options !== 'object') return;
    var needs = options.needs;
    if (!needs) return;

    var numericModuleId = typeof moduleId === 'number' && isFinite(moduleId) ? moduleId : idToModuleId(specifier);
    if (numericModuleId < 0) {
      numericModuleId = -numericModuleId;
    }

    // Grant capabilities using Exact.setModuleCapabilities
    if (typeof globalThis.Exact === 'object' &&
        typeof globalThis.Exact.setModuleCapabilities === 'function') {
      var caps = Array.isArray(needs) ? needs : [needs];
      globalThis.Exact.setModuleCapabilities(numericModuleId, caps);
    }
  };

  globalThis.require = function(specifier, options) {
    // Grant capabilities if provided
    grantCapabilities(specifier, options, 0);
    // globalThis.require carries no module parent, so package code that reaches
    // it must still be gated by the requesting frame's principal. (ENG-22618)
    checkImportGate(specifier);
    var internal = loadInternal(specifier);
    if (internal) return internal;
    return load(specifier, "");
  };
  globalThis.require.cache = cache;
  // require.resolve needs only the resolved path, so prefer the metadata-only
  // bridge that skips the full resolver's read + transpile + JSON-escape of the
  // module body (which require.resolve then discards). Fall back to the full
  // resolve bridge in runtimes/tests that don't expose the meta binding — the
  // record shape is identical apart from the omitted `source`. Hoisted, so the
  // localRequire.resolve closure above can reach it. (ENG-23007)
  function __exactResolvePath(specifier, referrer) {
    var resolveMeta = (typeof __exactModuleResolveMeta === 'function')
      ? __exactModuleResolveMeta
      : __exactModuleResolve;
    var json = resolveMeta(specifier, referrer || "");
    if (!json) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    var record = JSON.parse(json);
    if (record.error) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    return record.path || record.id || specifier;
  }
  globalThis.require.resolve = function(specifier) {
    return __exactResolvePath(specifier, "");
  };
  globalThis.require.resolve.paths = function(specifier) {
    return null;
  };
  Object.defineProperty(globalThis.require, 'main', {
    get: function() { return mainModule; },
    configurable: true,
    enumerable: true
  });
  var exactRequire = function(specifier) {
    // __exactRequire is a legacy/internal loader escape hatch used by runtime
    // bootstrap code. It is still reachable from package code, so it must carry
    // the same package-facing import gate as globalThis.require rather than
    // exposing load() directly. Loader-internal fan-out keeps using the closure
    // scoped load() primitive above. @ref LLP 0013#policy
    checkImportGate(specifier);
    return load(specifier, "");
  };
  exactRequire.cache = cache;
  exactRequire.resolve = globalThis.require.resolve;
  exactRequire.resolve.paths = globalThis.require.resolve.paths;
  Object.defineProperty(exactRequire, 'main', {
    get: function() { return mainModule; },
    configurable: true,
    enumerable: true
  });
  globalThis.__exactRequire = exactRequire;

  function __exactInstallGlobalBuffer() {
    var bufferModule;
    try {
      bufferModule = load('buffer', '');
    } catch (_bufferLoadErr) {
      return;
    }
    if (!bufferModule || typeof bufferModule.Buffer !== 'function') {
      return;
    }

    var BufferCtor = bufferModule.Buffer;
    if (!BufferCtor.__exactArrayBufferViewPatched) {
      var nativeFrom = BufferCtor.from;

      function normalizeBufferOffset(value, fallback) {
        if (value === undefined) return fallback;
        var number = Number(value);
        if (number !== number) return fallback;
        if (!isFinite(number)) return number;
        if (number < 0) return Math.ceil(number);
        return Math.floor(number);
      }

      function makeBufferBoundsError(which) {
        var err = new RangeError('"' + which + '" is outside of buffer bounds');
        err.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
        return err;
      }

      function promoteArrayBufferView(value, byteOffset, length) {
        var backing = value;
        if (
          typeof SharedArrayBuffer === 'function' &&
          Object.prototype.toString.call(value) === '[object SharedArrayBuffer]' &&
          value._buffer &&
          Object.prototype.toString.call(value._buffer) === '[object ArrayBuffer]'
        ) {
          backing = value._buffer;
        }

        var totalLength = backing.byteLength >>> 0;
        var offset = normalizeBufferOffset(byteOffset, 0);
        if (!isFinite(offset) || offset < 0 || offset > totalLength) {
          throw makeBufferBoundsError('offset');
        }

        var viewLength;
        if (length === undefined) {
          viewLength = totalLength - offset;
        } else {
          viewLength = normalizeBufferOffset(length, 0);
          if (!isFinite(viewLength) || viewLength < 0 || offset + viewLength > totalLength) {
            throw makeBufferBoundsError('length');
          }
        }

        var view = new Uint8Array(backing, offset, viewLength);
        Object.setPrototypeOf(view, BufferCtor.prototype);
        try {
          Object.defineProperty(view, '__isExactBuffer', {
            value: true,
            configurable: true,
            enumerable: false,
            writable: true
          });
        } catch (_bufferMarkerErr) {
          view.__isExactBuffer = true;
        }
        if (backing !== value) {
          try {
            Object.defineProperty(view, 'buffer', {
              configurable: true,
              enumerable: false,
              get: function() {
                return value;
              }
            });
          } catch (_bufferViewErr) {}
        }
        return view;
      }

      BufferCtor.from = function(value, encoding, length) {
        if (typeof ArrayBuffer === 'function' &&
            value instanceof ArrayBuffer &&
            value.constructor === ArrayBuffer) {
          return promoteArrayBufferView(value, encoding, length);
        }
        if (typeof SharedArrayBuffer === 'function' &&
            value instanceof SharedArrayBuffer &&
            value.constructor === SharedArrayBuffer) {
          return promoteArrayBufferView(value, encoding, length);
        }
        return nativeFrom.apply(this, arguments);
      };

      try {
        Object.defineProperty(BufferCtor, '__exactArrayBufferViewPatched', {
          value: true,
          configurable: true,
          enumerable: false,
          writable: false
        });
      } catch (_bufferPatchErr) {
        BufferCtor.__exactArrayBufferViewPatched = true;
      }
    }

    try {
      Object.defineProperty(globalThis, 'Buffer', {
        configurable: true,
        enumerable: true,
        writable: true,
        value: BufferCtor
      });
    } catch (_globalBufferErr) {
      globalThis.Buffer = BufferCtor;
    }
  }

  // When a shared runtime bundle will be loaded after the module loader,
  // skip eager Buffer installation and timer replacement here — the shared
  // bundle handles both via its own lazy getter system.  This avoids two
  // expensive require() calls during module-loader evaluation.
  // The env var is set by the C++ layer when a shared bundle is compiled in.
  if (!globalThis.__exactHasSharedRuntimeBundle) {
    __exactInstallGlobalBuffer();
    try {
      if (
        typeof globalThis.process === 'object' &&
        globalThis.process !== null &&
        globalThis.process.versions &&
        typeof globalThis.process.versions.node === 'string'
      ) {
        var nodeTimers = load('timers', '');
        if (nodeTimers && typeof nodeTimers.setTimeout === 'function') {
          globalThis.setTimeout = nodeTimers.setTimeout;
        }
        if (nodeTimers && typeof nodeTimers.clearTimeout === 'function') {
          globalThis.clearTimeout = nodeTimers.clearTimeout;
        }
        if (nodeTimers && typeof nodeTimers.setInterval === 'function') {
          globalThis.setInterval = nodeTimers.setInterval;
        }
        if (nodeTimers && typeof nodeTimers.clearInterval === 'function') {
          globalThis.clearInterval = nodeTimers.clearInterval;
        }
      }
    } catch (_timerInstallErr) {}
  }

  try {
    if (
      typeof globalThis.process === 'object' &&
      globalThis.process !== null &&
      globalThis.process.platform !== 'win32' &&
      typeof globalThis.__exactTrapSignal === 'function'
    ) {
      globalThis.__exactTrapSignal(25);
    }
  } catch (_sigxfszInstallErr) {}

  if (typeof globalThis.createExternalizableString !== 'function') {
    globalThis.createExternalizableString = function(value) {
      return String(value);
    };
  }
  if (typeof globalThis.createExternalizableTwoByteString !== 'function') {
    globalThis.createExternalizableTwoByteString = function(value) {
      return String(value);
    };
  }
  if (typeof globalThis.externalizeString !== 'function') {
    globalThis.externalizeString = function(value) {
      return String(value);
    };
  }
  if (typeof globalThis.isOneByteString !== 'function') {
    globalThis.isOneByteString = function(value) {
      var str = String(value);
      for (var i = 0; i < str.length; i++) {
        if (str.charCodeAt(i) > 0xFF) {
          return false;
        }
      }
      return true;
    };
  }

  // Polyfill dynamic import() using require()
  // import() returns a Promise that resolves to the module
  // ESM default export becomes { default: ... }, named exports are direct properties
  var importImpl = function(specifier, options, referrer, parent) {
    referrer = typeof referrer === 'string' ? referrer : "";
    // Gate synchronously: the microtask below detaches the requesting frame, so
    // frame-derived attribution must run now, while the package's frame is still
    // on the stack. Surface a denial as a rejected promise per import()
    // semantics rather than a synchronous throw. (ENG-22629)
    var gateError = null;
    try {
      checkImportGate(specifier);
      // A relative/absolute dynamic import can resolve to a DIFFERENT package
      // (`import('../sibling')`), which the raw-specifier gate above can't see.
      // The resolved-target gate in load() runs inside the microtask below where
      // the frame is already detached (currentPrincipalId would report an
      // unregistered sentinel and allow), so resolve + gate the target package's
      // name SYNCHRONOUSLY here while the requester frame is still on the stack.
      // (ENG-22637 review pass2)
      if (isPathSpecifier(specifier)) {
        var __itp = null;
        try {
          // This resolution only needs the target's package metadata, so use
          // the metadata-only bridge (ENG-23007) when available — the full
          // resolver would read + transpile + JSON-escape the module body a
          // second time on the JS thread for every relative/absolute dynamic
          // import, just for load() to redo it in the microtask (ENG-23481 #10).
          var __iresolve = (typeof __exactModuleResolveMeta === 'function')
            ? __exactModuleResolveMeta
            : __exactModuleResolve;
          var __irj = __iresolve(stripViteImportQuery(specifier), referrer);
          if (__irj) {
            var __irec = JSON.parse(__irj);
            if (!__irec.error) __itp = packageNameForRecord(__irec, parent);
          }
        } catch (e) { __itp = null; } // resolution failure: let load() surface it
        var __irp = parent && parent.__exactPackageName
          ? parent.__exactPackageName
          : packageNameFromPath(referrer);
        if (__itp && __itp !== __irp) checkImportGate(__itp); // denial propagates to the catch below
      }
    } catch (e) { gateError = e; }
    return Promise.resolve().then(function() {
      if (gateError) throw gateError;
      // Grant capabilities if provided
      grantCapabilities(specifier, options);

      var module = load(specifier, referrer, parent);
      // Wrap CommonJS modules to look like ESM: { default: module, ...module }
      // This allows: const mod = await import('foo'); mod.default or mod.something
      if (module && !module.__esModule) {
        var moduleType = typeof module;
        // Wrap objects and functions
        if (moduleType === 'object' || moduleType === 'function') {
          var wrapped = { default: module };
          // For objects, copy properties to wrapped
          if (moduleType === 'object') {
            for (var key in module) {
              if (module.hasOwnProperty(key)) {
                wrapped[key] = module[key];
              }
            }
          }
          return wrapped;
        }
      }
      return module;
    });
  };

  // Set as globalThis.import (use globalThis.import('foo') or globalThis['import']('foo'))
  if (typeof globalThis.import === 'undefined') {
    Object.defineProperty(globalThis, 'import', {
      value: importImpl,
      writable: false,
      enumerable: false,
      configurable: true
    });
  }

  // Also provide as importModule() for convenience (since import(...) triggers parser)
  globalThis.importModule = importImpl;

  // Wrap queueMicrotask to throw TypeError for non-function arguments (spec requirement)
  if (typeof queueMicrotask === 'function') {
    var _nativeQueueMicrotask = queueMicrotask;
    globalThis.queueMicrotask = function queueMicrotask(callback) {
      if (typeof callback !== 'function') {
        throw new TypeError("Failed to execute 'queueMicrotask': parameter 1 is not of type 'Function'.");
      }
      return _nativeQueueMicrotask(callback);
    };
  }

  // Fix console global to match WPT/spec requirements:
  // - non-enumerable on globalThis
  // - Symbol.toStringTag = "console"
  // - prototype chain: console -> {} -> Object.prototype
  if (typeof console !== 'undefined') {
    // Make the console property non-enumerable (spec requirement)
    Object.defineProperty(globalThis, 'console', {
      value: console,
      writable: true,
      enumerable: false,
      configurable: true
    });

    // Add Symbol.toStringTag so Object.prototype.toString returns "[object console]"
    if (typeof Symbol !== 'undefined' && Symbol.toStringTag) {
      Object.defineProperty(console, Symbol.toStringTag, {
        value: 'console',
        writable: false,
        enumerable: false,
        configurable: true
      });
    }

    // Fix prototype chain: console should have an empty prototype object
    // between it and Object.prototype (per WebIDL namespace spec)
    var consoleProto = Object.getPrototypeOf(console);
    if (consoleProto === Object.prototype || (consoleProto && Object.getOwnPropertyNames(consoleProto).length > 0)) {
      var emptyProto = Object.create(Object.prototype);
      Object.setPrototypeOf(console, emptyProto);
    }
  }
})();
