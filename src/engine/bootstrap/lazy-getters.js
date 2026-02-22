(function() {
  // Helper: define a lazy getter that deletes itself before calling the loader.
  // This prevents infinite recursion if the loader fails.
  function defineLazy(obj, prop, loader) {
    Object.defineProperty(obj, prop, {
      configurable: true, enumerable: true,
      get: function() {
        // Delete the getter FIRST to prevent re-entrancy
        delete obj[prop];
        loader();
        return obj[prop];
      }
    });
  }

  // crypto — lazy getter on globalThis.crypto
  defineLazy(globalThis, 'crypto', __exactEnsureWebCrypto);

  // localStorage / sessionStorage — lazy getters
  // Both need to clear BOTH getters since the storage JS sets both at once
  function loadStorage() {
    delete globalThis.localStorage;
    delete globalThis.sessionStorage;
    __exactEnsureWebStorage();
  }
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true, enumerable: true,
    get: function() { loadStorage(); return globalThis.localStorage; }
  });
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true, enumerable: true,
    get: function() { loadStorage(); return globalThis.sessionStorage; }
  });

  // FormData — lazy getter
  defineLazy(globalThis, 'FormData', __exactEnsureFormData);

  // Stream enhance — install stubs on process.stdout/stderr/stdin
  // that trigger loading when stream methods are first used
  var p = globalThis.process;
  if (p) {
    var streams = ['stdout', 'stderr', 'stdin'];
    var methods = ['on', 'once', 'pipe', 'cork', 'uncork', 'end',
                   'addListener', 'removeListener', 'emit'];
    for (var si = 0; si < streams.length; si++) {
      var stream = p[streams[si]];
      if (!stream) continue;
      for (var mi = 0; mi < methods.length; mi++) {
        (function(s, method) {
          if (!s[method]) {
            s[method] = function() {
              __exactEnsureStreamEnhance();
              return s[method].apply(s, arguments);
            };
          }
        })(stream, methods[mi]);
      }
    }
  }
})();
