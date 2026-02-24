(function() {
  if (typeof Array !== 'undefined' && typeof Array.isArray !== 'function') {
    Array.isArray = function(value) {
      return Object.prototype.toString.call(value) === '[object Array]';
    };
  }

  if (typeof Promise !== 'undefined' && typeof Promise.withResolvers !== 'function') {
    Promise.withResolvers = function() {
      var resolve;
      var reject;
      var promise = new Promise(function(res, rej) {
        resolve = res;
        reject = rej;
      });
      return {
        promise: promise,
        resolve: resolve,
        reject: reject
      };
    };
  }

  if (typeof Array.prototype.toSorted !== 'function') {
    Array.prototype.toSorted = function(compareFn) {
      var sorted = this.slice();
      return sorted.sort(compareFn);
    };
  }

  if (typeof Array.prototype.toReversed !== 'function') {
    Array.prototype.toReversed = function() {
      var result = [];
      for (var i = this.length - 1; i >= 0; i--) result.push(this[i]);
      return result;
    };
  }

  if (typeof FinalizationRegistry === 'undefined') {
    FinalizationRegistry = function(cleanupCallback) {
      if (!(this instanceof FinalizationRegistry)) {
        throw new TypeError('FinalizationRegistry must be called with new');
      }
      if (typeof cleanupCallback !== 'function') {
        throw new TypeError('FinalizationRegistry requires a callback');
      }
      this._entries = [];
      this._cleanup = cleanupCallback;
    };
    FinalizationRegistry.prototype.register = function(target, heldValue, unregisterToken) {
      if (!target || (typeof target !== 'object' && typeof target !== 'function')) {
        throw new TypeError('FinalizationRegistry target must be an object');
      }
      this._entries.push({
        target: target,
        heldValue: heldValue,
        token: unregisterToken
      });
      return true;
    };
    FinalizationRegistry.prototype.unregister = function(unregisterToken) {
      var removed = false;
      for (var i = this._entries.length - 1; i >= 0; i--) {
        if (this._entries[i].token === unregisterToken) {
          this._entries.splice(i, 1);
          removed = true;
        }
      }
      return removed;
    };
  }

  // Ensure process has EventEmitter-style helpers in Node-compat suites.
  // Node fixtures expect `process.on`, `emit`, etc. before any stream API
  // is imported, but stream enhancements are loaded lazily. Eagerly trigger
  // the enhancer here so Node compatibility tests get the standard hooks.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    typeof globalThis.__exactEnsureStreamEnhance === 'function' &&
    (typeof globalThis.process.on !== 'function' ||
      !globalThis.process.config)
  ) {
    try {
      globalThis.__exactEnsureStreamEnhance();
    } catch (err) {
      // Keep compatibility bootstrap resilient if stream enhancement cannot load.
    }
  }

  // Process streams can still be host-backed accessors in some bootstrap paths.
  // Pin stdout/stderr/stdin on the process object itself so repeated reads
  // return the same stream objects and util's write interception works
  // consistently. Also create a safe prototype shadow for the common copied
  // process object pattern used by Node tests.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    function __exactPatchProcessStreamPrototype() {
      var proto = Object.getPrototypeOf(globalThis.process);
      if (!proto || proto.__exactProcessProtoPatched) {
        return;
      }
      var patchedPrototype = Object.create(proto);
      var needsPrototypePatch = false;

      var keys = ['stdout', 'stderr', 'stdin', 'versions'].concat(Object.keys(globalThis.process));
      for (var i = 0; i < keys.length; i++) {
        var name = keys[i];
        var desc = Object.getOwnPropertyDescriptor(proto, name);
        if (name !== 'versions' && !desc) {
          continue;
        }
        if (
          name !== 'versions' &&
          !desc.get &&
          desc.set === undefined &&
          desc.writable !== false &&
          desc.configurable !== false
        ) {
          continue;
        }
        var stream;
        try {
          stream = globalThis.process[name];
        } catch (err) {
          continue;
        }
        if (stream === undefined) {
          continue;
        }
        try {
          Object.defineProperty(patchedPrototype, name, {
            value: stream,
            writable: true,
            configurable: true,
            enumerable: true
          });
          needsPrototypePatch = true;
        } catch (err) {}
      }

      if (needsPrototypePatch) {
        Object.setPrototypeOf(globalThis.process, patchedPrototype);
        try {
          Object.defineProperty(patchedPrototype, '__exactStreamProtoPatched', {
            value: true,
            writable: false,
            configurable: true,
            enumerable: false
          });
        } catch (err) {}
        try {
          Object.defineProperty(proto, '__exactProcessProtoPatched', {
            value: true,
            writable: false,
            configurable: true,
            enumerable: false
          });
        } catch (err) {}
      }

      try {
        Object.defineProperty(proto, '__exactStreamProtoPatched', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
    }

    function __exactPinStream(name) {
      var stream = globalThis.process[name];
      if (!stream) return;
      if ((name === 'stdout' || name === 'stderr') && stream.writable === undefined) {
        stream.writable = true;
      }
      Object.defineProperty(globalThis.process, name, {
        value: stream,
        writable: true,
        configurable: true,
        enumerable: true
      });
    }

    try {
      __exactPatchProcessStreamPrototype();
      if (!globalThis.process.__exactStreamStabilityPatched) {
        __exactPinStream('stdout');
        __exactPinStream('stderr');
        __exactPinStream('stdin');
        globalThis.process.__exactStreamStabilityPatched = true;
      }
    } catch (err) {
      // Keep compatibility bootstrap resilient if process stream patching fails.
    }
  }

  // Node/Bun fixtures assume process.config.variables is always available.
  // Normalize it here to avoid runtime crashes when the stream enhancer hasn't
  // run yet or didn't populate this field for some compatibility paths.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      if (globalThis.process.config === undefined || globalThis.process.config === null) {
        globalThis.process.config = { target_defaults: {}, variables: {} };
      } else if (
        typeof globalThis.process.config === 'object' &&
        !globalThis.process.config.variables
      ) {
        globalThis.process.config.variables = {};
      }
    } catch (err) {
      // Keep compatibility bootstrap resilient if process/config cannot be patched.
    }
  }

  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      if (!globalThis.process.features || typeof globalThis.process.features !== 'object') {
        globalThis.process.features = {
          inspector: true,
          debug: false,
          uv: false,
          ipv6: true,
          tls_alpn: false,
          tls_sni: false,
          tls_ocsp: false,
          tls: false,
        };
      } else {
        if (globalThis.process.features.tls === undefined) {
          globalThis.process.features.tls = false;
        }
        if (globalThis.process.features.tls_alpn === undefined) {
          globalThis.process.features.tls_alpn = false;
        }
        if (globalThis.process.features.tls_sni === undefined) {
          globalThis.process.features.tls_sni = false;
        }
        if (globalThis.process.features.tls_ocsp === undefined) {
          globalThis.process.features.tls_ocsp = false;
        }
      }
    } catch (err) {
      // Keep compatibility bootstrap resilient if process.features cannot be patched.
    }
  }

  function __exactInstallUmaskPolyfill() {
    if (typeof globalThis.process !== 'object' || globalThis.process === null) {
      return;
    }
    var proc = globalThis.process;
    if (typeof proc.umask === 'function') {
      return;
    }

    var currentUmask = 0o022;
    proc.umask = function(mask) {
      if (arguments.length === 0) {
        return currentUmask;
      }
      if (typeof mask === 'string') {
        if (!/^\d+$/.test(mask)) {
          throw new TypeError("Bad argument");
        }
        mask = parseInt(mask, 8);
      } else if (typeof mask !== 'number' || (mask | 0) !== mask) {
        throw new TypeError("Bad argument");
      }
      if (mask < 0 || mask > 0o7777 || !isFinite(mask)) {
        throw new RangeError("Bad argument");
      }
      var previousUmask = currentUmask;
      currentUmask = mask & 0o7777;
      return previousUmask;
    };
  }
  __exactInstallUmaskPolyfill();

  // Node-oriented packages expect `process.versions.node` to exist.
  // In some Hermes runtimes process.versions is a host-managed accessor object
  // that may not include the Node key even though the process object is writable.
  // Normalize it here so later checks and Node compatibility tests can rely on it.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      function __exactApplyVersionsPatch(target, patchedVersions) {
        if (!target || typeof target !== 'object') return false;
        try {
          var desc = Object.getOwnPropertyDescriptor(target, 'versions');
          if (!desc) {
            try {
              Object.defineProperty(target, 'versions', {
                value: patchedVersions,
                writable: true,
                configurable: true,
                enumerable: false
              });
              return true;
            } catch (err) {}
            try {
              target.versions = patchedVersions;
              return true;
            } catch (err) {}
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
              return true;
            } catch (err) {}
            try {
              target.versions = patchedVersions;
              return true;
            } catch (err) {}
            return false;
          }
          try {
            Object.defineProperty(target, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: !!desc.configurable,
              enumerable: !!desc.enumerable
            });
            return true;
          } catch (err) {}
          try {
            target.versions = patchedVersions;
            return true;
          } catch (err) {}
        } catch (err) {}
        return false;
      }

      var processVersions = globalThis.process.versions;
      processVersions = processVersions && typeof processVersions === 'object'
        ? processVersions
        : {};
      var patchedVersions = {
        node: processVersions.node || '24.13.1',
        v8: processVersions.v8 || '0.0.0',
        uv: processVersions.uv || '0.0.0',
        zlib: processVersions.zlib || '1.3.1',
        brotli: processVersions.brotli || '0.0.0',
        ares: processVersions.ares || '0.0.0',
        modules: processVersions.modules || '127',
        nghttp2: processVersions.nghttp2 || '0.0.0',
        napi: processVersions.napi || '9',
        llhttp: processVersions.llhttp || '0.0.0',
        uvwasi: processVersions.uvwasi || '0.0.0',
        unicode: processVersions.unicode || '15.1',
        openssl: processVersions.openssl || '0.0.0',
        hermes: processVersions.hermes || '0.12.0',
        exact: processVersions.exact || '0.1.0'
      };
      try {
        __exactApplyVersionsPatch(globalThis.process, patchedVersions);
      } catch (err) {}

      try {
        var processVersionPrototype = Object.getPrototypeOf(globalThis.process);
        while (
          processVersionPrototype &&
          processVersionPrototype !== Object.prototype &&
          typeof processVersionPrototype === 'object'
        ) {
          if (__exactApplyVersionsPatch(processVersionPrototype, patchedVersions)) {
            break;
          }
          processVersionPrototype = Object.getPrototypeOf(processVersionPrototype);
        }
      } catch (err) {}

      try {
        var versionsOwner = Object.getPrototypeOf(globalThis.process);
        var versionsDescriptor = versionsOwner &&
          Object.getOwnPropertyDescriptor(versionsOwner, 'versions');
        if (
          !versionsDescriptor ||
          typeof versionsDescriptor.get === 'function' ||
          versionsDescriptor.set === undefined ||
          !('value' in versionsDescriptor) ||
          versionsDescriptor.writable !== true
        ) {
          try {
            Object.defineProperty(versionsOwner, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: true,
              enumerable: false
            });
          } catch (err) {
            try {
              var patchedVersionsPrototype = Object.create(versionsOwner);
              Object.defineProperty(patchedVersionsPrototype, 'versions', {
                value: patchedVersions,
                writable: true,
                configurable: true,
                enumerable: false
              });
              Object.setPrototypeOf(globalThis.process, patchedVersionsPrototype);
            } catch (err2) {}
          }
        }
      } catch (err) {}

      try {
        var processVersionsDescriptor = Object.getOwnPropertyDescriptor(
          globalThis.process,
          'versions'
        );
        if (
          !processVersionsDescriptor ||
          typeof processVersionsDescriptor.get === 'function' ||
          !('value' in processVersionsDescriptor) ||
          processVersionsDescriptor.writable !== true ||
          processVersionsDescriptor.enumerable
        ) {
          try {
            Object.defineProperty(globalThis.process, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: true,
              enumerable: false
            });
          } catch (err) {}
        }
      } catch (err) {}

      if (processVersions.node) {
        globalThis.process.version = 'v' + String(processVersions.node).replace(/^v/, '');
      }
      // Node compat: set process.release.name to 'node' for compatibility
      // process is a HostObject, so we need Object.defineProperty to override
      try {
        var existingRelease = globalThis.process.release;
        var releaseObj = (existingRelease && typeof existingRelease === 'object') ?
          Object.assign({}, existingRelease, { name: 'node' }) : { name: 'node' };
        Object.defineProperty(globalThis.process, 'release', {
          value: releaseObj, writable: true, configurable: true, enumerable: true
        });
      } catch (e) {}
    } catch (err) {
      // Keep bootstrap resilient if process version patching fails.
    }
  }

  function __exactNeedsUrlCompatPatch() {
    if (typeof globalThis.URL !== 'function') {
      return false;
    }
    if (typeof globalThis.URLSearchParams !== 'function') {
      return false;
    }

    try {
      var base = new globalThis.URL('http://test@example.net');
      if (base.pathname !== '/') {
        return true;
      }

      var hostOnly = new globalThis.URL('https://username:password@host:8000/path');
      hostOnly.host = '\t' + 'test';
      if (hostOnly.host !== 'test:8000') {
        return true;
      }

      var invalidProtocol = new globalThis.URL('http://test@example.net');
      invalidProtocol.protocol = 'file';
      if (invalidProtocol.href !== 'http://test@example.net/') {
        return true;
      }
      return false;
    } catch (e) {
      return true;
    }
  }

  function __exactNeedsHexDigit(char) {
    return (
      char && char.length === 1 &&
      ((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F') || (char >= 'a' && char <= 'f'))
    );
  }

  function __exactNeedsUserinfoPatch() {
    if (typeof globalThis.URL !== 'function') {
      return false;
    }
    var url = new URL('http://example.net');
    var usernameValue = '\u0000\u0001\t\n\r\u001F !\"#$%&\'()*+,-./09:;<=>?@AZ[\\\\]^_`az{|}~\u007F\u0080\u0081Éé';
    var expectedUsername = '%00%01%09%0A%0D%1F%20!%22%23$%&\'()*+,-.%2F09%3A%3B%3C%3D%3E%3F%40AZ%5B%5C%5D%5E_%60az%7B%7C%7D~%7F%C2%80%C2%81%C3%89%C3%A9';
    url.username = usernameValue;
    return url.username !== expectedUsername;
  }

  function __exactHasExplicitPort(value) {
    value = String(value);
    if (value.charAt(0) === '[') {
      var close = value.indexOf(']');
      return close !== -1 && value.indexOf(':', close + 1) !== -1;
    }
    return value.indexOf(':') !== -1;
  }

  function __exactNeedsRootPath(urlObj) {
    if (!urlObj || typeof urlObj.protocol !== 'string') {
      return false;
    }
    var protocol = urlObj.protocol;
    return protocol === 'http:' || protocol === 'https:' || protocol === 'ftp:' ||
      protocol === 'file:' || protocol === 'ws:' || protocol === 'wss:';
  }

  function __exactPatchUrlConstructors() {
    if (typeof globalThis.URL !== 'function' || typeof globalThis.URL.prototype !== 'object') {
      return;
    }

    var urlProto = globalThis.URL.prototype;

    var pathnameDesc = Object.getOwnPropertyDescriptor(urlProto, 'pathname');
    if (pathnameDesc && pathnameDesc.get && !pathnameDesc.get.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'pathname', {
        configurable: true,
        get: function() {
          var value = pathnameDesc.get.call(this);
          if (value === '' && __exactNeedsRootPath(this) && this.host) {
            return '/';
          }
          return value;
        },
        set: pathnameDesc.set
      });
      pathnameDesc.get.__exactCompatPatched = true;
    }

    var protocolDesc = Object.getOwnPropertyDescriptor(urlProto, 'protocol');
    if (protocolDesc && protocolDesc.set && !protocolDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'protocol', {
        configurable: true,
        get: protocolDesc.get,
        set: function(value) {
          var before = String(this.href || '');
          protocolDesc.set.call(this, value);
          if (this.pathname === '' && __exactNeedsRootPath(this) && this.host && String(this.href) === before) {
            this.pathname = '/';
          }
        }
      });
      protocolDesc.set.__exactCompatPatched = true;
    }

    var hostDesc = Object.getOwnPropertyDescriptor(urlProto, 'host');
    if (hostDesc && hostDesc.set && !hostDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'host', {
        configurable: true,
        get: hostDesc.get,
        set: function(value) {
          var raw = String(value);
          if (raw !== '' && this.port && !__exactHasExplicitPort(raw)) {
            hostDesc.set.call(this, raw + ':' + this.port);
            return;
          }
          hostDesc.set.call(this, raw);
        }
      });
      hostDesc.set.__exactCompatPatched = true;
    }

    function __exactIsUserinfoUnescaped(value) {
      var code = value.charCodeAt(0);
      if (code >= 0x30 && code <= 0x39) return true;
      if (code >= 0x41 && code <= 0x5A) return true;
      if (code >= 0x61 && code <= 0x7A) return true;
      if (
        code === 0x21 || code === 0x24 || code === 0x26 || code === 0x27 || code === 0x28 ||
        code === 0x29 || code === 0x2A || code === 0x2B || code === 0x2C || code === 0x2D ||
        code === 0x2E || code === 0x5F || code === 0x7E || code === 0x25
      ) {
        return true;
      }
      return false;
    }

    function __exactSanitizeUserinfo(value) {
      var out = '';
      for (var i = 0; i < value.length; i++) {
        var c = value.charAt(i);
        if (
          c === '%' &&
          __exactNeedsHexDigit(value.charAt(i + 1)) &&
          __exactNeedsHexDigit(value.charAt(i + 2))
        ) {
          out += value.slice(i, i + 3);
          i += 2;
          continue;
        }
        if (__exactIsUserinfoUnescaped(c)) {
          out += c;
        } else {
          out += encodeURIComponent(c);
        }
      }
      return out;
    }

    var usernameDesc = Object.getOwnPropertyDescriptor(urlProto, 'username');
    if (usernameDesc && usernameDesc.set && !usernameDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'username', {
        configurable: true,
        get: usernameDesc.get,
        set: function(value) {
          return usernameDesc.set.call(this, __exactSanitizeUserinfo(String(value)));
        }
      });
      usernameDesc.set.__exactCompatPatched = true;
    }

    var passwordDesc = Object.getOwnPropertyDescriptor(urlProto, 'password');
    if (passwordDesc && passwordDesc.set && !passwordDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'password', {
        configurable: true,
        get: passwordDesc.get,
        set: function(value) {
          return passwordDesc.set.call(this, __exactSanitizeUserinfo(String(value)));
        }
      });
      passwordDesc.set.__exactCompatPatched = true;
    }
  }

  function __exactDecodeUrlEncodedFormBody(bodyText) {
    var decoder;
    if (typeof TextDecoder === 'undefined') {
      return String(bodyText);
    }
    try {
      decoder = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });
    } catch (err) {
      decoder = new TextDecoder('utf-8');
    }
    return decoder.decode(bodyText);
  }

  function __exactPatchUrlEncodedFormData() {
    if (typeof globalThis.Request !== 'function' || typeof globalThis.Response !== 'function') {
      return;
    }
    if (typeof globalThis.FormData !== 'function' || typeof URLSearchParams === 'undefined') {
      return;
    }
    if (typeof globalThis.FormData.prototype.append !== 'function') {
      return;
    }

    var requestFormData = globalThis.Request && globalThis.Request.prototype &&
      globalThis.Request.prototype.formData;
    if (typeof requestFormData === 'function' && !requestFormData.__exactCompatPatched) {
      globalThis.Request.prototype.formData = async function() {
        var contentType = this.headers && typeof this.headers.get === 'function'
          ? this.headers.get('content-type')
          : '';
        if (typeof contentType === 'string' && contentType.toLowerCase().indexOf('multipart/form-data') === 0) {
          return requestFormData.call(this);
        }
        var bodyBuffer = await this.arrayBuffer();
        var bodyText = __exactDecodeUrlEncodedFormBody(new Uint8Array(bodyBuffer));
        var parsed = new URLSearchParams(bodyText);
        var formData = new FormData();
        for (var i = 0; i < parsed.length; i++) {
          var pair = parsed[i];
          formData.append(pair[0], pair[1]);
        }
        return formData;
      };
      globalThis.Request.prototype.formData.__exactCompatPatched = true;
    }

    var responseFormData = globalThis.Response && globalThis.Response.prototype &&
      globalThis.Response.prototype.formData;
    if (typeof responseFormData === 'function' && !responseFormData.__exactCompatPatched) {
      globalThis.Response.prototype.formData = async function() {
        var contentType = this.headers && typeof this.headers.get === 'function'
          ? this.headers.get('content-type')
          : '';
        if (typeof contentType === 'string' && contentType.toLowerCase().indexOf('multipart/form-data') === 0) {
          return responseFormData.call(this);
        }
        var bodyBuffer = await this.arrayBuffer();
        var bodyText = __exactDecodeUrlEncodedFormBody(new Uint8Array(bodyBuffer));
        var parsed = new URLSearchParams(bodyText);
        var formData = new FormData();
        for (var i = 0; i < parsed.length; i++) {
          var pair = parsed[i];
          formData.append(pair[0], pair[1]);
        }
        return formData;
      };
      globalThis.Response.prototype.formData.__exactCompatPatched = true;
    }
  }

  if (__exactNeedsUrlCompatPatch() || __exactNeedsUserinfoPatch()) {
    __exactPatchUrlConstructors();
    __exactPatchUrlEncodedFormData();
  }

  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
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
              configurable: true,
              enumerable: true
            });
            return true;
          }
        } catch (err) {}
        try {
          target.execPath = value;
          return true;
        } catch (err) {}
        return false;
      }

      var __exactExecPathValue = globalThis.process.execPath;
      if (__exactExecPathValue === undefined) {
        __exactExecPathValue = '';
      }
      __exactDefineExecPath(globalThis.process, __exactExecPathValue);
      var __exactProcessProto = Object.getPrototypeOf(globalThis.process);
      if (
        __exactProcessProto &&
        __exactProcessProto !== Object.prototype &&
        __exactProcessProto !== globalThis.process &&
        typeof __exactProcessProto === 'object'
      ) {
        __exactDefineExecPath(__exactProcessProto, __exactExecPathValue);
      }
      if (__exactProcessProto && __exactProcessProto !== Object.prototype && typeof __exactProcessProto === 'object') {
        var processExecPathPrototype = Object.getPrototypeOf(__exactProcessProto);
        while (
          processExecPathPrototype &&
          processExecPathPrototype !== Object.prototype &&
          typeof processExecPathPrototype === 'object'
        ) {
          if (__exactDefineExecPath(processExecPathPrototype, __exactExecPathValue)) {
            break;
          }
          processExecPathPrototype = Object.getPrototypeOf(processExecPathPrototype);
        }
      }
    } catch (err) {}

    // Compatibility helpers expected by a small subset of Node fixture patterns.
    // Exposed globally so rewritten fixture files (created at runtime) still see
    // `ok`/`failed` helpers without requiring '../common'.
    try {
      var __global = (typeof globalThis !== 'undefined') ? globalThis : (typeof global !== 'undefined' ? global : null);
      function __exactBuildCompatFailed(value) {
        if (typeof value === 'function') {
          try {
            return value() === undefined;
          } catch (e) {}
          return false;
        }
        return !value;
      }
      if (__global && typeof globalThis.__exactRequire === 'function') {
        var __exactAssert = globalThis.__exactRequire('assert');
        if (__global && __exactAssert && typeof __exactAssert.ok === 'function') {
          __global.failed = __exactBuildCompatFailed;
          if (typeof __global.badly !== 'function') {
            __global.badly = function() {
              return undefined;
            };
          }
        }
        if (__global && typeof __global.ok !== 'function' && __exactAssert && typeof __exactAssert.ok === 'function') {
          __global.ok = function(value, message) {
            __exactAssert.ok(value, message);
          };
        }
      }
      if (__global && typeof __global.failed !== 'function') {
        __global.failed = __exactBuildCompatFailed;
      }
      if (__global && typeof __global.badly !== 'function') {
        __global.badly = function() {
          return undefined;
        };
      }
      if (__global && typeof __global.ok !== 'function') {
        __global.ok = function(value, message) {
          if (!value) {
            throw new Error(message || 'The expression evaluated to a falsy value');
          }
        };
      }
    } catch (err) {}
  }

  // Child-process IPC bootstrap for exact child runtimes.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    globalThis.process.env &&
    globalThis.process.env.EXACT_IPC_FD
  ) {
    var exactIpcFd = Number(globalThis.process.env.EXACT_IPC_FD);
    if (isFinite(exactIpcFd) && exactIpcFd >= 0) {
      var exactIpcBuffer = '';
      var exactIpcConnected = true;
      var exactIpcPollTimer = null;
      var exactIpcPollActive = true;
      var exactIpcPollInterval = 10;

      function exactToString(bytes) {
        if (typeof TextDecoder === 'function') {
          try {
            return new TextDecoder().decode(bytes);
          } catch (err) {}
        }
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
          out += String.fromCharCode(bytes[i]);
        }
        return out;
      }

      function exactBuildIpcPacket(type, data) {
        return JSON.stringify({ __exactIpc: true, type: type, data: data }) + '\\n';
      }

      function exactCreateIpcError(code, message) {
        var err = new Error(message);
        err.code = code;
        return err;
      }

      function exactCloseIpc() {
        if (!exactIpcConnected) return;
        exactIpcConnected = false;
        exactIpcPollActive = false;
        if (exactIpcPollTimer) {
          clearTimeout(exactIpcPollTimer);
          exactIpcPollTimer = null;
        }
        globalThis.process.connected = false;
        globalThis.process.channel = null;
        if (typeof globalThis.__exactFsClose === 'function') {
          try {
            globalThis.__exactFsClose(exactIpcFd);
          } catch (err) {}
        }
        setTimeout(function() {
          globalThis.process.emit('disconnect');
        }, 0);
      }

      function exactProcessIncomingPackets(rawData) {
        if (!rawData || !rawData.length) return;
        exactIpcBuffer += exactToString(rawData);
        while (exactIpcBuffer.length > 0) {
          var lineEnd = exactIpcBuffer.indexOf('\\n');
          if (lineEnd < 0) {
            return;
          }
          var line = exactIpcBuffer.slice(0, lineEnd);
          exactIpcBuffer = exactIpcBuffer.slice(lineEnd + 1);
          if (!line) continue;
          try {
            var packet = JSON.parse(line);
            if (!packet || packet.__exactIpc !== true) continue;
            if (packet.type === 'message') {
              globalThis.process.emit('message', packet.data);
            } else if (packet.type === 'disconnect') {
              exactCloseIpc();
            }
          } catch (err) {}
        }
      }

      function exactPollIpc() {
        if (!exactIpcPollActive || !globalThis.process) {
          return;
        }
        if (!exactIpcConnected) {
          return;
        }
        if (
          typeof globalThis.__exactFsRead === 'function' &&
          globalThis.__exactFsRead
        ) {
          var chunk;
          try {
            chunk = globalThis.__exactFsRead(exactIpcFd, 65536, -1);
          } catch (err) {
            exactCloseIpc();
            return;
          }
          if (chunk && chunk.length) {
            exactProcessIncomingPackets(chunk);
          }
        }
        if (exactIpcPollActive) {
          exactIpcPollTimer = setTimeout(exactPollIpc, exactIpcPollInterval);
        }
      }

      globalThis.process.connected = true;
      globalThis.process.channel = { fd: exactIpcFd };
      globalThis.process.send = function(message, sendHandle, opts, callback) {
        if (!exactIpcConnected) {
          var ipcError = exactCreateIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is closed');
          if (typeof callback === 'function') {
            setTimeout(function() {
              callback(ipcError);
            }, 0);
          }
          return false;
        }
        if (typeof sendHandle === 'function') {
          callback = sendHandle;
          sendHandle = undefined;
          opts = undefined;
        } else if (typeof opts === 'function') {
          callback = opts;
          opts = undefined;
        }
        var packet = exactBuildIpcPacket('message', message);
        var written = false;
        if (typeof globalThis.__exactFsWrite === 'function') {
          try {
            written = globalThis.__exactFsWrite(exactIpcFd, packet, -1) > 0;
          } catch (err) {
            written = false;
          }
        }
        if (typeof callback === 'function') {
          setTimeout(function() {
            callback(written ? null : exactCreateIpcError('ERR_IPC_CHANNEL_CLOSED', 'IPC channel is closed'));
          }, 0);
        }
        return written;
      };

      globalThis.process.disconnect = function() {
        if (!exactIpcConnected) {
          throw exactCreateIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is already disconnected');
        }
        if (typeof globalThis.__exactFsWrite === 'function' && exactIpcConnected) {
          try {
            var disconnectPacket = exactBuildIpcPacket('disconnect');
            globalThis.__exactFsWrite(exactIpcFd, disconnectPacket, -1);
          } catch (err) {}
        }
        exactCloseIpc();
      };

      exactIpcPollTimer = setTimeout(exactPollIpc, 0);
    }
  }

  // When running compat tests, auto-load bun:test so test/describe/it/expect
  // globals are available even if the test file doesn't explicitly import them.
  // This matches Bun's behavior where these globals are always present.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    globalThis.process.env &&
    globalThis.process.env.EXACT_COMPAT_TEST === '1' &&
    typeof globalThis.__exactRequire === 'function' &&
    typeof globalThis.test !== 'function'
  ) {
    try {
      // Ensure 'global' is defined — bun-adapter.js uses it but it may not
      // be set up this early in bootstrap.
      if (typeof global === 'undefined') {
        globalThis.global = globalThis;
      }
      globalThis.__exactRequire('bun:test');
      // Also load the 'bun' module to merge shim properties (unsafe, Glob, etc.)
      // onto the runtime-provided globalThis.Bun object.
      globalThis.__exactRequire('bun');
    } catch (err) {
      // Keep bootstrap resilient if bun:test/bun cannot be loaded.
    }
  }
})();
