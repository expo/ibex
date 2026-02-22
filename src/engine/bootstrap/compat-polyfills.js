(function() {
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
      var processVersions = globalThis.process.versions;
      processVersions = processVersions && typeof processVersions === 'object'
        ? processVersions
        : {};
      Object.defineProperty(globalThis.process, 'versions', {
        value: {
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
        },
        writable: true,
        enumerable: true,
        configurable: true
      });
      if (processVersions.node) {
        globalThis.process.version = 'v' + String(processVersions.node).replace(/^v/, '');
      }
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
})();
