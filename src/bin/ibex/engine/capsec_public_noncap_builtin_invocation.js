(function runNonCapabilityBuiltinInvocation(config) {
  var own = Object.prototype.hasOwnProperty;
  var sourceOperationAttempted = false;

  function valueType(value) {
    return value === null ? "null" : typeof value;
  }

  function exactObjectKeys(value, expected) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    var keys = Object.keys(value).sort();
    var wanted = expected.slice().sort();
    if (keys.length !== wanted.length) return false;
    for (var index = 0; index < keys.length; index++) {
      if (keys[index] !== wanted[index]) return false;
    }
    return true;
  }

  function sameStringArray(value, expected) {
    if (!Array.isArray(value) || value.length !== expected.length) {
      return false;
    }
    for (var index = 0; index < value.length; index++) {
      if (value[index] !== expected[index]) return false;
    }
    return true;
  }

  function sameJsonStringArguments(value, expected) {
    if (!Array.isArray(value) || value.length !== expected.length) {
      return false;
    }
    for (var index = 0; index < value.length; index++) {
      var argument = value[index];
      if (
        !exactObjectKeys(argument, ["kind", "value"]) ||
        argument.kind !== "json" ||
        argument.value !== expected[index]
      ) {
        return false;
      }
    }
    return true;
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Independently close the HTTP recipe family at execution time. Generic
  // constructed receivers or root-call arguments must not turn a newly
  // catalogued HTTP method into an executable claim.
  function isReviewedBoundedHttpInvocation(invocation) {
    if (
      invocation.invocationSchema !==
        "ibex/capsec-builtin-call-invocation/1" ||
      invocation.kind !== "builtin-export-call" ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_http"
    ) {
      return true;
    }
    var descriptor = invocation.sourceDescriptor;
    var exportName = invocation.exportName;
    var segments =
      typeof exportName === "string" ? exportName.split(".") : [];
    var prototype = segments.length === 2;
    if (
      invocation.moduleSpecifier !== "node:http" ||
      invocation.templateId !== "node-http-idle-v1" ||
      descriptor.exportName !== exportName ||
      !exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) ||
      descriptor.kind !== "builtin-export" ||
      descriptor.valueShape !== "callable" ||
      descriptor.sourceRef !==
        "src/builtins/http.js#exports:" + exportName ||
      !sameStringArray(descriptor.exportIdioms, [
        prototype
          ? "exported-constructor-prototype"
          : "module-exports-object",
      ]) ||
      !sameStringArray(descriptor.moduleSpecifiers, [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ]) ||
      !exactObjectKeys(descriptor.access, ["kind", "path"]) ||
      descriptor.access.kind !==
        (prototype ? "prototype-property" : "export-property") ||
      !sameStringArray(
        descriptor.access.path,
        prototype
          ? [segments[0], "prototype", segments[1]]
          : [exportName],
      ) ||
      !Array.isArray(invocation.arguments) ||
      !exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) ||
      invocation.bodyEntryProof.kind !== "normal-return-from-source-call"
    ) {
      return false;
    }
    var setup = invocation.setup;
    var resultType;
    var rootArguments = null;
    if (exportName === "_checkInvalidHeaderChar") {
      rootArguments = ["ibex"];
      resultType = "boolean";
    } else if (exportName === "_checkIsHttpToken") {
      rootArguments = ["x-ibex"];
      resultType = "boolean";
    } else if (exportName === "createServer") {
      rootArguments = [];
      resultType = "object";
    } else if (exportName === "validateHeaderName") {
      rootArguments = ["x-ibex"];
      resultType = "undefined";
    } else if (exportName === "validateHeaderValue") {
      rootArguments = ["x-ibex", "ibex"];
      resultType = "undefined";
    }
    if (rootArguments !== null) {
      return (
        invocation.bodyEntryProof.resultType === resultType &&
        exactObjectKeys(setup, ["kind"]) &&
        setup.kind === "root-call" &&
        sameJsonStringArguments(invocation.arguments, rootArguments)
      );
    }
    if (exportName === "Server" || exportName === "Server.constructor") {
      resultType = "object";
      return (
        invocation.bodyEntryProof.resultType === resultType &&
        exactObjectKeys(setup, ["kind"]) &&
        setup.kind === "construct-target" &&
        invocation.arguments.length === 0
      );
    }
    var owner;
    if (exportName === "Agent.destroy") {
      owner = "Agent";
      resultType = "undefined";
    } else if (exportName === "Server.close") {
      owner = "Server";
      resultType = "object";
    } else if (
      exportName === "Server.closeAllConnections" ||
      exportName === "Server.closeIdleConnections"
    ) {
      owner = "Server";
      resultType = "undefined";
    } else if (
      exportName === "Server.ref" ||
      exportName === "Server.unref"
    ) {
      owner = "Server";
      resultType = "object";
    } else {
      return false;
    }
    return (
      invocation.bodyEntryProof.resultType === resultType &&
      exactObjectKeys(setup, [
        "constructorArguments",
        "kind",
        "ownerExportName",
      ]) &&
      setup.kind === "constructed-owner" &&
      setup.ownerExportName === owner &&
      Array.isArray(setup.constructorArguments) &&
      setup.constructorArguments.length === 0 &&
      invocation.arguments.length === 0
    );
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // A TLSSocket created without a transport has no native owner token, TLS
  // engine, selector, listener, or pending timer. Keep this exact lifecycle
  // vocabulary separate from transport-binding TLS operations.
  function isReviewedIdleTlsSocketInvocation(invocation) {
    if (
      invocation.invocationSchema !==
        "ibex/capsec-builtin-call-invocation/1" ||
      invocation.kind !== "builtin-export-call" ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_tls" ||
      invocation.exportName === "getCiphers"
    ) {
      return true;
    }
    var descriptor = invocation.sourceDescriptor;
    var exportName = invocation.exportName;
    var segments =
      typeof exportName === "string" ? exportName.split(".") : [];
    var prototype = segments.length === 2;
    if (
      invocation.moduleSpecifier !== "node:tls" ||
      invocation.templateId !== "node-tls-pure-v1" ||
      descriptor.exportName !== exportName ||
      !exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) ||
      descriptor.kind !== "builtin-export" ||
      descriptor.valueShape !== "callable" ||
      descriptor.sourceRef !==
        "src/builtins/tls.js#exports:" + exportName ||
      !sameStringArray(descriptor.exportIdioms, [
        prototype
          ? "exported-constructor-prototype"
          : "module-exports-object",
      ]) ||
      !sameStringArray(descriptor.moduleSpecifiers, ["node:tls", "tls"]) ||
      !exactObjectKeys(descriptor.access, ["kind", "path"]) ||
      descriptor.access.kind !==
        (prototype ? "prototype-property" : "export-property") ||
      !sameStringArray(
        descriptor.access.path,
        prototype
          ? ["TLSSocket", "prototype", segments[1]]
          : ["TLSSocket"],
      ) ||
      !Array.isArray(invocation.arguments) ||
      invocation.arguments.length !== 0 ||
      !exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) ||
      invocation.bodyEntryProof.kind !== "normal-return-from-source-call" ||
      invocation.bodyEntryProof.resultType !== "object"
    ) {
      return false;
    }
    var setup = invocation.setup;
    if (exportName === "TLSSocket") {
      return (
        exactObjectKeys(setup, ["kind"]) &&
        setup.kind === "construct-target"
      );
    }
    if (
      exportName !== "TLSSocket.close" &&
      exportName !== "TLSSocket.destroy" &&
      exportName !== "TLSSocket.ref" &&
      exportName !== "TLSSocket.unref"
    ) {
      return false;
    }
    return (
      exactObjectKeys(setup, [
        "constructorArguments",
        "kind",
        "ownerExportName",
      ]) &&
      setup.kind === "constructed-owner" &&
      setup.ownerExportName === "TLSSocket" &&
      Array.isArray(setup.constructorArguments) &&
      setup.constructorArguments.length === 0
    );
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // A fresh udp4 Socket has an owner stamp but no native handle, binding,
  // polling timer, or peer route. Keep that exact closed vocabulary separate
  // from network-bearing dgram operations at the final execution boundary.
  function isReviewedIdleDgramInvocation(invocation) {
    if (
      invocation.invocationSchema !==
        "ibex/capsec-builtin-call-invocation/1" ||
      invocation.kind !== "builtin-export-call" ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_dgram"
    ) {
      return true;
    }
    var descriptor = invocation.sourceDescriptor;
    var exportName = invocation.exportName;
    var segments =
      typeof exportName === "string" ? exportName.split(".") : [];
    var prototype = segments.length === 2;
    if (
      invocation.moduleSpecifier !== "node:dgram" ||
      invocation.templateId !== "node-dgram-idle-v1" ||
      descriptor.exportName !== exportName ||
      !exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) ||
      descriptor.kind !== "builtin-export" ||
      descriptor.valueShape !== "callable" ||
      descriptor.sourceRef !==
        "src/builtins/dgram.js#exports:" + exportName ||
      !sameStringArray(descriptor.exportIdioms, [
        prototype
          ? "exported-constructor-prototype"
          : "module-exports-object",
      ]) ||
      !sameStringArray(descriptor.moduleSpecifiers, ["dgram", "node:dgram"]) ||
      !exactObjectKeys(descriptor.access, ["kind", "path"]) ||
      descriptor.access.kind !==
        (prototype ? "prototype-property" : "export-property") ||
      !sameStringArray(
        descriptor.access.path,
        prototype
          ? [segments[0], "prototype", segments[1]]
          : [exportName],
      ) ||
      !exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) ||
      invocation.bodyEntryProof.kind !== "normal-return-from-source-call" ||
      invocation.bodyEntryProof.resultType !== "object"
    ) {
      return false;
    }
    function isUdp4Argument(value) {
      return (
        exactObjectKeys(value, ["kind", "value"]) &&
        value.kind === "json" &&
        value.value === "udp4"
      );
    }
    if (exportName === "Socket" || exportName === "Socket.constructor") {
      return (
        exactObjectKeys(invocation.setup, ["kind"]) &&
        invocation.setup.kind === "construct-target" &&
        Array.isArray(invocation.arguments) &&
        invocation.arguments.length === 1 &&
        isUdp4Argument(invocation.arguments[0])
      );
    }
    if (exportName === "createSocket") {
      return (
        exactObjectKeys(invocation.setup, ["kind"]) &&
        invocation.setup.kind === "root-call" &&
        Array.isArray(invocation.arguments) &&
        invocation.arguments.length === 1 &&
        isUdp4Argument(invocation.arguments[0])
      );
    }
    if (
      exportName !== "Socket.close" &&
      exportName !== "Socket.ref" &&
      exportName !== "Socket.unref"
    ) {
      return false;
    }
    return (
      exactObjectKeys(invocation.setup, [
        "constructorArguments",
        "kind",
        "ownerExportName",
      ]) &&
      invocation.setup.kind === "constructed-owner" &&
      invocation.setup.ownerExportName === "Socket" &&
      Array.isArray(invocation.setup.constructorArguments) &&
      invocation.setup.constructorArguments.length === 1 &&
      isUdp4Argument(invocation.setup.constructorArguments[0]) &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 0
    );
  }

  // X509Certificate.toString is a narrowly reviewed state projection. Keep
  // its fresh receiver and own-prototype path exact so another certificate
  // method cannot borrow this no-decision receipt.
  function isReviewedX509StateInvocation(invocation) {
    if (
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "exact_crypto" ||
      invocation.exportName !== "X509Certificate.toString"
    ) {
      return true;
    }
    var descriptor = invocation.sourceDescriptor;
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:crypto" &&
      invocation.templateId === "exact-crypto-bounded-v1" &&
      exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) &&
      descriptor.kind === "builtin-export" &&
      descriptor.exportName === "X509Certificate.toString" &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/crypto.js#exports:X509Certificate.toString" &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, [
        "crypto",
        "exact:crypto",
        "node:crypto",
      ]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "prototype-property" &&
      sameStringArray(descriptor.access.path, [
        "X509Certificate",
        "prototype",
        "toString",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "constructorArguments",
        "kind",
        "ownerExportName",
      ]) &&
      invocation.setup.kind === "constructed-owner" &&
      invocation.setup.ownerExportName === "X509Certificate" &&
      Array.isArray(invocation.setup.constructorArguments) &&
      invocation.setup.constructorArguments.length === 1 &&
      exactObjectKeys(invocation.setup.constructorArguments[0], [
        "kind",
        "value",
      ]) &&
      invocation.setup.constructorArguments[0].kind === "json" &&
      invocation.setup.constructorArguments[0].value ===
        "ibex-x509-fixture" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 0 &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind === "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "string"
    );
  }

  // Keep the source-only key wrappers and terminal escape formatter closed at
  // the loaded-engine boundary. A new crypto or readline callable must not
  // inherit these zero-decision literals.
  function isReviewedPureCompatibilityInvocation(invocation) {
    var descriptor = invocation.sourceDescriptor;
    if (!descriptor) return true;
    var sourceKey = descriptor.sourceKey;
    var exportName = invocation.exportName;
    var cryptoKeyWrapper =
      sourceKey === "exact_crypto" &&
      (exportName === "createPrivateKey" ||
        exportName === "createPublicKey");
    var readlineCsi =
      sourceKey === "node_readline" && exportName === "CSI";
    if (!cryptoKeyWrapper && !readlineCsi) {
      return (
        sourceKey !== "node_readline" ||
        exportName === "Interface.close" ||
        exportName === "Interface.pause"
      );
    }
    var expectedModuleSpecifier = cryptoKeyWrapper
      ? "node:crypto"
      : "node:readline";
    var expectedTemplateId = cryptoKeyWrapper
      ? "exact-crypto-bounded-v1"
      : "node-readline-pure-v1";
    var expectedIdioms = cryptoKeyWrapper
      ? ["object-binding", "object-source"]
      : ["module-exports-object"];
    var expectedModuleSpecifiers = cryptoKeyWrapper
      ? ["crypto", "exact:crypto", "node:crypto"]
      : [
          "node:readline",
          "node:readline/promises",
          "readline",
          "readline/promises",
        ];
    var expectedSourceRef = cryptoKeyWrapper
      ? "src/builtins/crypto.js#exports:" + exportName
      : "src/builtins/readline.js#exports:CSI";
    var argument = invocation.arguments && invocation.arguments[0];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === expectedModuleSpecifier &&
      invocation.templateId === expectedTemplateId &&
      exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) &&
      descriptor.kind === "builtin-export" &&
      descriptor.exportName === exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef === expectedSourceRef &&
      sameStringArray(descriptor.exportIdioms, expectedIdioms) &&
      sameStringArray(
        descriptor.moduleSpecifiers,
        expectedModuleSpecifiers,
      ) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "export-property" &&
      sameStringArray(descriptor.access.path, [exportName]) &&
      exactObjectKeys(invocation.setup, ["kind"]) &&
      invocation.setup.kind === "root-call" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(argument, ["kind", "value"]) &&
      argument.kind === "json" &&
      (cryptoKeyWrapper
        ? argument.value === "ibex-key"
        : Array.isArray(argument.value) &&
          argument.value.length === 1 &&
          argument.value[0] === "31m") &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType ===
        (cryptoKeyWrapper ? "object" : "string")
    );
  }

  function isReviewedReadlineInterfaceLifecycleInvocation(invocation) {
    var descriptor = invocation.sourceDescriptor;
    var exportName = invocation.exportName;
    var methodName =
      exportName === "Interface.close"
        ? "close"
        : exportName === "Interface.pause"
          ? "pause"
          : null;
    if (
      !descriptor ||
      descriptor.sourceKey !== "node_readline" ||
      methodName === null
    ) {
      return true;
    }
    var setup = invocation.setup;
    var close = methodName === "close";
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:readline" &&
      invocation.templateId === "node-readline-pure-v1" &&
      exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) &&
      descriptor.kind === "builtin-export" &&
      descriptor.exportName === exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/readline.js#exports:" + exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, [
        "node:readline",
        "node:readline/promises",
        "readline",
        "readline/promises",
      ]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "prototype-property" &&
      sameStringArray(descriptor.access.path, [
        "Interface",
        "prototype",
        methodName,
      ]) &&
      exactObjectKeys(
        setup,
        close
          ? ["kind", "ownerExportName", "terminal"]
          : [
              "cleanupMethod",
              "kind",
              "ownerExportName",
              "terminal",
            ],
      ) &&
      setup.kind ===
        (close
          ? "readline-interface-owner"
          : "readline-interface-pause-owner") &&
      setup.ownerExportName === "Interface" &&
      setup.terminal === false &&
      (close || setup.cleanupMethod === "close") &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 0 &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType ===
        (close ? "undefined" : "object")
    );
  }

  function isReviewedKeyObjectEqualsInvocation(invocation) {
    var descriptor = invocation.sourceDescriptor;
    if (
      !descriptor ||
      descriptor.sourceKey !== "exact_crypto" ||
      invocation.exportName !== "KeyObject.equals"
    ) {
      return true;
    }
    var setup = invocation.setup;
    var argument = invocation.arguments && invocation.arguments[0];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:crypto" &&
      invocation.templateId === "exact-crypto-bounded-v1" &&
      exactObjectKeys(descriptor, [
        "access",
        "exportIdioms",
        "exportName",
        "kind",
        "moduleSpecifiers",
        "sourceKey",
        "sourceRef",
        "valueShape",
      ]) &&
      descriptor.kind === "builtin-export" &&
      descriptor.exportName === "KeyObject.equals" &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/crypto.js#exports:KeyObject.equals" &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, [
        "crypto",
        "exact:crypto",
        "node:crypto",
      ]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "prototype-property" &&
      sameStringArray(descriptor.access.path, [
        "KeyObject",
        "prototype",
        "equals",
      ]) &&
      exactObjectKeys(setup, [
        "bytes",
        "keyType",
        "kind",
        "ownerExportName",
      ]) &&
      setup.kind === "key-object-pair-owner" &&
      setup.ownerExportName === "KeyObject" &&
      setup.keyType === "secret" &&
      Array.isArray(setup.bytes) &&
      setup.bytes.length === 4 &&
      setup.bytes[0] === 0x69 &&
      setup.bytes[1] === 0x62 &&
      setup.bytes[2] === 0x65 &&
      setup.bytes[3] === 0x78 &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(argument, ["kind", "name"]) &&
      argument.kind === "setup-value" &&
      argument.name === "peer" &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "boolean"
    );
  }

  // Output-shape capture is deliberately non-coercing. Primitive values are
  // retained exactly; functions, symbols, and undefined use the established
  // null payload; compound values retain their actual shape without invoking
  // toJSON, getters, proxy enumeration, or user String conversion.
  function rawReturn(value) {
    var shape = value === null
      ? "null"
      : (Array.isArray(value) ? "array" : typeof value);
    var encoded = null;
    if (
      shape === "null" ||
      shape === "boolean" ||
      shape === "number" ||
      shape === "string"
    ) {
      encoded = value;
    } else if (shape === "bigint") {
      encoded = String(value);
    } else if (shape === "array") {
      encoded = [];
    }
    return {
      kind: "return",
      rawValueShape: shape,
      value: encoded,
      errorCode: null,
    };
  }

  function rawThrow(error) {
    return {
      kind: "throw",
      rawValueShape: "throw",
      value: null,
      errorCode:
        error && typeof error.code === "string" && error.code.length > 0
          ? error.code
          : "ERR_IBEX_PUBLIC_BUILTIN_THROW",
    };
  }

  function failure(kind, extra) {
    var out = {
      kind: kind,
      moduleSpecifier: config.moduleSpecifier,
      exportName: config.exportName,
    };
    if (extra) {
      var keys = Object.keys(extra);
      for (var index = 0; index < keys.length; index++) {
        out[keys[index]] = extra[keys[index]];
      }
    }
    return out;
  }

  function resolveExport(moduleValue, descriptor) {
    var access = descriptor.access;
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // These exact instance projections require fresh harness-owned receivers;
    // generic constructed-property reads remain unavailable.
    if (access.kind === "constructed-instance-property") {
      if (config.kind !== "builtin-export-read" || access.path.length !== 1) {
        return { error: failure("access-mismatch") };
      }
      var segments = descriptor.exportName.split(".");
      if (segments.length !== 2 || segments[1] !== access.path[0]) {
        return { error: failure("access-mismatch") };
      }
      var instance;
      if (
        access.path[0] === "closed" &&
        config.setup &&
        config.setup.kind === "stream-owner" &&
        config.setup.endedInput === false &&
        segments[0] === config.setup.ownerExportName
      ) {
        instance = createStreamInstance(
          moduleValue,
          config.setup.ownerExportName,
          false,
        );
        var streamDescriptor = Object.getOwnPropertyDescriptor(
          instance,
          access.path[0],
        );
        if (!streamDescriptor || typeof streamDescriptor.get !== "function") {
          return {
            error: failure("shape-mismatch", {
              expectedShape: "own-accessor",
            }),
          };
        }
      } else if (
        descriptor.sourceKey === "exact_crypto" &&
        descriptor.exportName === "X509Certificate.raw" &&
        access.path[0] === "raw" &&
        config.setup &&
        config.setup.kind === "constructed-owner" &&
        config.setup.ownerExportName === "X509Certificate" &&
        exactObjectKeys(config.setup, [
          "constructorArguments",
          "kind",
          "ownerExportName",
        ]) &&
        Array.isArray(config.setup.constructorArguments) &&
        config.setup.constructorArguments.length === 1 &&
        exactObjectKeys(config.setup.constructorArguments[0], [
          "kind",
          "value",
        ]) &&
        config.setup.constructorArguments[0].kind === "json" &&
        config.setup.constructorArguments[0].value === "ibex-x509-fixture"
      ) {
        var x509Owner = moduleValue.X509Certificate;
        if (typeof x509Owner !== "function") {
          return { error: failure("setup-mismatch") };
        }
        instance = Reflect.construct(x509Owner, ["ibex-x509-fixture"]);
        var x509Descriptor = Object.getOwnPropertyDescriptor(
          x509Owner.prototype,
          "raw",
        );
        if (!x509Descriptor || typeof x509Descriptor.get !== "function") {
          return {
            error: failure("shape-mismatch", {
              expectedShape: "prototype-accessor",
            }),
          };
        }
      } else {
        return { error: failure("access-mismatch") };
      }
      if (!instance) {
        return {
          error: failure("setup-mismatch"),
        };
      }
      sourceOperationAttempted = true;
      return { value: instance[access.path[0]] };
    }
    var value = moduleValue;
    if (access.kind === "module-value") {
      if (config.kind === "builtin-export-read") {
        sourceOperationAttempted = true;
      }
      return { value: value };
    }
    for (var index = 0; index < access.path.length; index++) {
      var key = access.path[index];
      var last = index === access.path.length - 1;
      if (
        value === null ||
        (typeof value !== "object" && typeof value !== "function")
      ) {
        return {
          error: failure("missing", { segment: key, available: [] }),
        };
      }
      var holder = value;
      if (last && access.kind === "inherited-prototype-property") {
        if (own.call(holder, key)) {
          return {
            error: failure("access-mismatch", {
              segment: key,
              expectedAccess: access.kind,
            }),
          };
        }
        holder = Object.getPrototypeOf(holder);
        while (holder && !own.call(holder, key)) {
          holder = Object.getPrototypeOf(holder);
        }
        if (!holder) {
          return {
            error: failure("missing", {
              segment: key,
              available: Object.getOwnPropertyNames(value).slice(0, 32),
            }),
          };
        }
      } else if (!own.call(holder, key)) {
        return {
          error: failure("missing", {
            segment: key,
            available: Object.getOwnPropertyNames(value).slice(0, 32),
          }),
        };
      }
      if (last) {
        var propertyDescriptor = Object.getOwnPropertyDescriptor(holder, key);
        if (
          descriptor.valueShape === "accessor" &&
          (!propertyDescriptor || typeof propertyDescriptor.get !== "function")
        ) {
          return {
            error: failure("shape-mismatch", {
              expectedShape: descriptor.valueShape,
            }),
          };
        }
        if (
          (descriptor.valueShape === "data" ||
            descriptor.valueShape === "callable") &&
          (!propertyDescriptor || !("value" in propertyDescriptor))
        ) {
          return {
            error: failure("shape-mismatch", {
              expectedShape: descriptor.valueShape,
            }),
          };
        }
      }
      if (last && config.kind === "builtin-export-read") {
        sourceOperationAttempted = true;
      }
      value = holder[key];
    }
    return { value: value };
  }

  function createStreamInstance(moduleValue, ownerExportName, ended) {
    var owner =
      ownerExportName === "default"
        ? moduleValue
        : moduleValue[ownerExportName];
    if (typeof owner !== "function") {
      throw new TypeError("missing authored stream owner");
    }
    var options = {};
    if (ownerExportName === "Readable" || ownerExportName === "Duplex") {
      options.read = function () {};
    }
    if (ownerExportName === "Writable" || ownerExportName === "Duplex") {
      options.write = function (chunk, encoding, callback) {
        callback();
      };
    }
    if (ownerExportName === "Transform") {
      options.transform = function (chunk, encoding, callback) {
        callback(null, chunk);
      };
    }
    var constructorArguments =
      ownerExportName === "Stream" || ownerExportName === "default"
        ? []
        : [options];
    var instance = Reflect.construct(owner, constructorArguments);
    if (ended && typeof instance.push === "function") {
      instance.push(null);
    }
    return instance;
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // materialize and audit the exact harness-owned Interface lifecycle.
  function createReadlineInterfaceInstance(moduleValue) {
    var owner = moduleValue.Interface;
    if (typeof owner !== "function") {
      throw new TypeError("missing authored readline Interface owner");
    }
    var allowedEvents = ["close", "data", "end", "error"];
    var listeners = Object.create(null);
    var state = {
      valid: true,
      resumeCalls: 0,
      pauseCalls: 0,
      closeEvents: 0,
      listeners: listeners,
      initialVerified: false,
    };
    var input = {
      on: function (eventName, listener) {
        if (
          allowedEvents.indexOf(eventName) === -1 ||
          typeof listener !== "function" ||
          own.call(listeners, eventName)
        ) {
          state.valid = false;
          return this;
        }
        listeners[eventName] = listener;
        return this;
      },
      removeListener: function (eventName, listener) {
        if (
          !own.call(listeners, eventName) ||
          listeners[eventName] !== listener
        ) {
          state.valid = false;
          return this;
        }
        delete listeners[eventName];
        return this;
      },
      resume: function () {
        state.resumeCalls++;
        return this;
      },
      pause: function () {
        state.pauseCalls++;
        return this;
      },
    };
    var receiver = Reflect.construct(owner, [
      { input: input, output: null, terminal: false },
    ]);
    state.initialVerified =
      state.valid &&
      state.resumeCalls === 1 &&
      state.pauseCalls === 0 &&
      Object.keys(listeners).sort().join(",") ===
        allowedEvents.slice().sort().join(",");
    receiver.once("close", function () {
      state.closeEvents++;
    });
    return { receiver: receiver, state: state };
  }

  function verifyReadlineInterfacePause(receiver, state) {
    return (
      state.initialVerified === true &&
      state.valid === true &&
      receiver.closed === false &&
      receiver.paused === true &&
      receiver._paused === true &&
      state.resumeCalls === 1 &&
      state.pauseCalls === 1 &&
      state.closeEvents === 0 &&
      receiver.listenerCount("close") === 1 &&
      Object.keys(state.listeners).sort().join(",") ===
        ["close", "data", "end", "error"].join(",")
    );
  }

  function verifyReadlineInterfaceClose(
    receiver,
    state,
    expectedPauseCalls,
  ) {
    return (
      state.initialVerified === true &&
      state.valid === true &&
      receiver.closed === true &&
      state.resumeCalls === 1 &&
      state.pauseCalls === expectedPauseCalls &&
      state.closeEvents === 1 &&
      receiver.listenerCount("close") === 0 &&
      Object.keys(state.listeners).length === 0
    );
  }

  function materialize(argument, moduleValue, bindings) {
    if (!argument || typeof argument.kind !== "string") {
      throw new TypeError("invalid authored builtin argument");
    }
    if (argument.kind === "json") return argument.value;
    if (argument.kind === "noop-function") return function () {};
    if (argument.kind === "throwing-function") {
      return function () {
        throw new Error(argument.errorMessage);
      };
    }
    if (argument.kind === "regexp") {
      return new RegExp(argument.source, argument.flags);
    }
    if (argument.kind === "event-emitter") {
      var EventEmitter = moduleValue.EventEmitter || moduleValue;
      return Reflect.construct(EventEmitter, []);
    }
    if (argument.kind === "uint8-array") {
      return new Uint8Array(argument.bytes);
    }
    if (argument.kind === "buffer") {
      var BufferOwner = moduleValue.Buffer || globalThis.Buffer;
      if (!BufferOwner || typeof BufferOwner.from !== "function") {
        throw new TypeError("missing authored builtin Buffer owner");
      }
      return BufferOwner.from(argument.bytes);
    }
    if (argument.kind === "bigint") {
      return BigInt(argument.value);
    }
    if (argument.kind === "setup-value") {
      if (!own.call(bindings, argument.name)) {
        throw new TypeError("missing authored builtin setup value");
      }
      return bindings[argument.name];
    }
    if (argument.kind === "constant-function") {
      return function () {
        return argument.value;
      };
    }
    if (argument.kind === "stream-instance") {
      return createStreamInstance(
        moduleValue,
        argument.ownerExportName,
        argument.ended,
      );
    }
    if (argument.kind === "abort-signal") {
      return new AbortController().signal;
    }
    if (argument.kind === "zlib-input") {
      if (argument.ownerExportName === "Inflate") {
        return moduleValue.deflateSync("ibex");
      }
      if (argument.ownerExportName === "Gunzip") {
        return moduleValue.gzipSync("ibex");
      }
      if (argument.ownerExportName === "InflateRaw") {
        return moduleValue.deflateRawSync("ibex");
      }
      if (argument.ownerExportName === "Unzip") {
        return moduleValue.gzipSync("ibex");
      }
      if (argument.ownerExportName === "BrotliDecompress") {
        return moduleValue.brotliCompressSync("ibex");
      }
      return "ibex";
    }
    throw new TypeError("unknown authored builtin argument kind");
  }

  function materializeList(arguments_, moduleValue, bindings) {
    var out = [];
    for (var index = 0; index < arguments_.length; index++) {
      out.push(materialize(arguments_[index], moduleValue, bindings));
    }
    return out;
  }

  try {
    var cleanupPerformed = false;
    var inputLifecycleVerified = false;
    var readlineLifecycleState = null;
    if (
      !isReviewedBoundedHttpInvocation(config) ||
      !isReviewedIdleTlsSocketInvocation(config) ||
      !isReviewedIdleDgramInvocation(config) ||
      !isReviewedX509StateInvocation(config) ||
      !isReviewedPureCompatibilityInvocation(config) ||
      !isReviewedReadlineInterfaceLifecycleInvocation(config) ||
      !isReviewedKeyObjectEqualsInvocation(config)
    ) {
      return failure("contract-mismatch");
    }
    var moduleValue = require(config.moduleSpecifier);
    var resolved = resolveExport(moduleValue, config.sourceDescriptor);
    if (resolved.error) return resolved.error;
    var target = resolved.value;

    if (config.kind === "builtin-export-read") {
      if (
        config.sourceDescriptor.valueShape === "data" &&
        typeof target === "function"
      ) {
        return failure("shape-mismatch", {
          expectedShape: config.sourceDescriptor.valueShape,
          actualType: typeof target,
        });
      }
      var readSuccess = { valueType: valueType(target) };
      if (config.captureRawOutput === true) {
        readSuccess.sourceOperationAttempted = sourceOperationAttempted;
        readSuccess.rawOutput = rawReturn(target);
      }
      return failure("return", readSuccess);
    }

    if (config.kind !== "builtin-export-call") {
      return failure("unsupported-invocation-kind");
    }
    if (typeof target !== "function") {
      return failure("shape-mismatch", {
        expectedShape: "callable",
        actualType: valueType(target),
      });
    }

    var setup = config.setup;
    var bindings = {};
    var receiver;
    var result;
    var dispatchKind;
    if (setup.kind === "root-call") {
      receiver = moduleValue;
      dispatchKind = "call";
    } else if (setup.kind === "construct-target") {
      dispatchKind = "construct";
    } else if (setup.kind === "constructed-owner") {
      var owner = moduleValue[setup.ownerExportName];
      if (typeof owner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(
        owner,
        materializeList(setup.constructorArguments, moduleValue, bindings),
      );
      dispatchKind = "prototype-call";
    } else if (setup.kind === "key-object-pair-owner") {
      var keyObjectOwner = moduleValue[setup.ownerExportName];
      if (typeof keyObjectOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var keyBytes = new Uint8Array(setup.bytes);
      receiver = Reflect.construct(keyObjectOwner, [
        setup.keyType,
        keyBytes,
      ]);
      bindings.peer = Reflect.construct(keyObjectOwner, [
        setup.keyType,
        new Uint8Array(setup.bytes),
      ]);
      dispatchKind = "prototype-call";
    } else if (
      setup.kind === "readline-interface-owner" ||
      setup.kind === "readline-interface-pause-owner"
    ) {
      var readlineInstance = createReadlineInterfaceInstance(moduleValue);
      receiver = readlineInstance.receiver;
      readlineLifecycleState = readlineInstance.state;
      if (!readlineLifecycleState.initialVerified) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      dispatchKind = "prototype-call";
    } else if (setup.kind === "buffer-owner") {
      var bufferOwner = moduleValue[setup.ownerExportName];
      if (typeof bufferOwner !== "function" || !moduleValue.Buffer) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = moduleValue.Buffer.from(setup.bytes);
      if (!(receiver instanceof bufferOwner)) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      dispatchKind = "prototype-call";
    } else if (setup.kind === "call-tracker-owner") {
      var trackerOwner = moduleValue[setup.ownerExportName];
      if (typeof trackerOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(trackerOwner, []);
      bindings.tracked = receiver.calls(
        function () {},
        setup.trackedExpectedCalls,
      );
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-owner") {
      var zlibOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibOwner, []);
      if (
        setup.ensureNativeStream &&
        (typeof receiver._ensureNativeStream !== "function" ||
          receiver._ensureNativeStream() !== true)
      ) {
        if (typeof receiver._closeNativeStream === "function") {
          receiver._closeNativeStream();
          cleanupPerformed = true;
        }
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
          expectedNativeStream: true,
        });
      }
      dispatchKind = "prototype-call";
    } else if (setup.kind === "stream-owner") {
      receiver = createStreamInstance(
        moduleValue,
        setup.ownerExportName,
        setup.endedInput,
      );
      dispatchKind = "prototype-call";
    } else {
      return failure("unsupported-setup", { setupKind: setup.kind });
    }

    var callArguments = materializeList(
      config.arguments,
      moduleValue,
      bindings,
    );
    try {
      sourceOperationAttempted = true;
      if (dispatchKind === "construct") {
        result = Reflect.construct(target, callArguments);
      } else {
        result = Reflect.apply(target, receiver, callArguments);
      }
      if (
        setup.kind === "readline-interface-owner" ||
        setup.kind === "readline-interface-pause-owner"
      ) {
        var pauseVerified =
          setup.kind !== "readline-interface-pause-owner" ||
          verifyReadlineInterfacePause(
            receiver,
            readlineLifecycleState,
          );
        if (setup.kind === "readline-interface-pause-owner") {
          receiver.close();
        }
        inputLifecycleVerified =
          pauseVerified &&
          verifyReadlineInterfaceClose(
            receiver,
            readlineLifecycleState,
            setup.kind === "readline-interface-owner" ? 1 : 2,
          );
        cleanupPerformed = inputLifecycleVerified;
        if (!inputLifecycleVerified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
          });
        }
      }
    } finally {
      if (
        setup.kind === "zlib-owner" &&
        receiver &&
        typeof receiver._closeNativeStream === "function"
      ) {
        receiver._closeNativeStream();
        cleanupPerformed = true;
      }
    }
    function finishResult(settledResult) {
      result = settledResult;
      var proofKind =
        (config.bodyEntryProof && config.bodyEntryProof.kind) ||
        "normal-return-from-source-call";
      if (config.captureRawOutput === true) {
        var capturedSuccess = {
          valueType: valueType(result),
          dispatchKind: dispatchKind,
          bodyEntryProof: proofKind,
          sourceOperationAttempted: sourceOperationAttempted,
          rawOutput: rawReturn(result),
        };
        if (setup.kind === "zlib-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
        }
        if (
          setup.kind === "readline-interface-owner" ||
          setup.kind === "readline-interface-pause-owner"
        ) {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.inputLifecycleVerified =
            inputLifecycleVerified;
        }
        return failure("return", capturedSuccess);
      }
      var actualResultType = valueType(result);
      if (actualResultType !== config.bodyEntryProof.resultType) {
        return failure("result-type-mismatch", {
          expectedResultType: config.bodyEntryProof.resultType,
          actualResultType: actualResultType,
          dispatchKind: dispatchKind,
        });
      }
      var success = {
        valueType: actualResultType,
        dispatchKind: dispatchKind,
        bodyEntryProof: proofKind,
      };
      if (setup.kind === "zlib-owner") {
        success.cleanupPerformed = cleanupPerformed;
      }
      if (
        setup.kind === "readline-interface-owner" ||
        setup.kind === "readline-interface-pause-owner"
      ) {
        success.cleanupPerformed = cleanupPerformed;
        success.inputLifecycleVerified = inputLifecycleVerified;
      }
      return failure("return", success);
    }

    if (
      config.bodyEntryProof &&
      config.bodyEntryProof.kind === "settled-return-from-source-call"
    ) {
      return Promise.resolve(result).then(
        finishResult,
        function (error) {
          return failure("throw", {
            errorName: String((error && error.name) || "Error"),
            errorMessage: String((error && error.message) || error),
          });
        },
      );
    }
    return finishResult(result);
  } catch (error) {
    if (config.captureRawOutput === true && sourceOperationAttempted) {
      var capturedThrow = {
        sourceOperationAttempted: true,
        rawOutput: rawThrow(error),
      };
      if (cleanupPerformed) capturedThrow.cleanupPerformed = true;
      return failure("throw", capturedThrow);
    }
    var thrown = {
      errorName: String((error && error.name) || "Error"),
      errorMessage: String((error && error.message) || error),
    };
    if (cleanupPerformed) thrown.cleanupPerformed = true;
    return failure("throw", thrown);
  }
})
