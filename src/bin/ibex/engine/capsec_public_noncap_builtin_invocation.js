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

  function sameByteArray(value, expected) {
    if (!Array.isArray(value) || value.length !== expected.length) {
      return false;
    }
    for (var index = 0; index < value.length; index++) {
      if (
        !Number.isInteger(value[index]) ||
        value[index] < 0 ||
        value[index] > 255 ||
        value[index] !== expected[index]
      ) {
        return false;
      }
    }
    return true;
  }

  function sameByteView(value, expected) {
    if (
      value === null ||
      typeof value !== "object" ||
      !ArrayBuffer.isView(value) ||
      value.byteLength !== expected.length ||
      value.length !== expected.length
    ) {
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
  // Keep the exact fresh net terminal vocabulary closed at the loaded-engine
  // boundary. Each receiver has no native handle, but its close event and
  // final state must be observed before the fixture may return.
  function isReviewedIdleNetTerminalInvocation(invocation) {
    var usesNetTerminalSetup =
      invocation &&
      invocation.setup &&
      invocation.setup.kind === "net-terminal-owner";
    if (
      invocation.invocationSchema !==
        "ibex/capsec-builtin-call-invocation/1" ||
      invocation.kind !== "builtin-export-call" ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_net"
    ) {
      return !usesNetTerminalSetup;
    }
    var exportName = invocation.exportName;
    var ownerExportName = null;
    if (exportName === "Server.close") {
      ownerExportName = "Server";
    } else if (
      exportName === "Socket.close" ||
      exportName === "Socket.resetAndDestroy"
    ) {
      ownerExportName = "Socket";
    } else if (
      exportName === "Stream.close" ||
      exportName === "Stream.resetAndDestroy"
    ) {
      ownerExportName = "Stream";
    } else {
      return !usesNetTerminalSetup;
    }
    var descriptor = invocation.sourceDescriptor;
    var methodName = exportName.split(".")[1];
    return (
      invocation.moduleSpecifier === "node:net" &&
      invocation.templateId === "node-net-bounded-v1" &&
      descriptor.exportName === exportName &&
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
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/net.js#exports:" + exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["net", "node:net"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "prototype-property" &&
      sameStringArray(descriptor.access.path, [
        ownerExportName,
        "prototype",
        methodName,
      ]) &&
      exactObjectKeys(invocation.setup, ["kind", "ownerExportName"]) &&
      invocation.setup.kind === "net-terminal-owner" &&
      invocation.setup.ownerExportName === ownerExportName &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 0 &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind === "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
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
      invocation.exportName === "getCiphers" ||
      invocation.exportName === "Server" ||
      invocation.exportName === "Server.constructor" ||
      invocation.exportName === "createServer"
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
  // Fresh TLS Server construction owns no transport, native listener, or
  // accept loop, but it does mint one private owner token. Admit only the
  // three exact constructor surfaces whose dedicated setup closes the result
  // and proves delayed token retirement before the harness returns.
  function isReviewedIdleTlsServerInvocation(invocation) {
    if (
      invocation.invocationSchema !==
        "ibex/capsec-builtin-call-invocation/1" ||
      invocation.kind !== "builtin-export-call" ||
      !invocation.sourceDescriptor ||
      (invocation.sourceDescriptor.sourceKey !== "node_tls" &&
        invocation.sourceDescriptor.sourceKey !== "node_https")
    ) {
      return true;
    }
    var descriptor = invocation.sourceDescriptor;
    var exportName = invocation.exportName;
    if (
      exportName !== "Server" &&
      exportName !== "Server.constructor" &&
      exportName !== "createServer"
    ) {
      return descriptor.sourceKey === "node_tls";
    }
    var https = descriptor.sourceKey === "node_https";
    var prototype = exportName === "Server.constructor";
    var expectedSetupKind =
      exportName === "createServer"
        ? "tls-server-root-call"
        : "tls-server-construct-target";
    if (
      invocation.moduleSpecifier !== (https ? "node:https" : "node:tls") ||
      invocation.templateId !==
        (https ? "node-https-idle-v1" : "node-tls-pure-v1") ||
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
        "src/builtins/" + (https ? "https.js" : "tls.js") +
          "#exports:" + exportName ||
      !sameStringArray(descriptor.exportIdioms, [
        prototype
          ? "exported-constructor-prototype"
          : https
            ? "member-assignment"
            : "module-exports-object",
      ]) ||
      !sameStringArray(
        descriptor.moduleSpecifiers,
        https ? ["https", "node:https"] : ["node:tls", "tls"],
      ) ||
      !exactObjectKeys(descriptor.access, ["kind", "path"]) ||
      descriptor.access.kind !==
        (prototype ? "prototype-property" : "export-property") ||
      !sameStringArray(
        descriptor.access.path,
        prototype
          ? ["Server", "prototype", "constructor"]
          : [exportName],
      ) ||
      !exactObjectKeys(invocation.setup, ["kind"]) ||
      invocation.setup.kind !== expectedSetupKind ||
      !Array.isArray(invocation.arguments) ||
      invocation.arguments.length !== 0 ||
      !exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) ||
      invocation.bodyEntryProof.kind !== "normal-return-from-source-call" ||
      invocation.bodyEntryProof.resultType !== "object"
    ) {
      return false;
    }
    return true;
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
      invocation.bodyEntryProof.resultType !==
        (exportName === "Socket.dropMembership" ? "undefined" : "object")
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
      exportName !== "Socket.dropMembership" &&
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
      (exportName === "Socket.dropMembership"
        ? invocation.arguments.length === 1 &&
          exactObjectKeys(invocation.arguments[0], ["kind", "value"]) &&
          invocation.arguments[0].kind === "json" &&
          invocation.arguments[0].value === "224.0.0.1"
        : invocation.arguments.length === 0)
    );
  }

  function isZlibSyncEncoderInvocation(invocation) {
    return (
      invocation &&
      invocation.sourceDescriptor &&
      invocation.sourceDescriptor.sourceKey === "node_zlib" &&
      (invocation.exportName === "brotliCompressSync" ||
        invocation.exportName === "deflateSync" ||
        invocation.exportName === "deflateRawSync" ||
        invocation.exportName === "gzipSync")
    );
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // These four one-shot encoders receive one exact four-byte Buffer and
  // retain no codec stream. Keep their source descriptor, dispatch, and input
  // closed at the final loaded-engine boundary.
  function isReviewedZlibSyncEncoderInvocation(invocation) {
    if (!isZlibSyncEncoderInvocation(invocation)) return true;
    var descriptor = invocation.sourceDescriptor;
    var argument = invocation.arguments && invocation.arguments[0];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "object-binding",
        "object-source",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "export-property" &&
      sameStringArray(descriptor.access.path, [invocation.exportName]) &&
      exactObjectKeys(invocation.setup, ["kind"]) &&
      invocation.setup.kind === "root-call" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(argument, ["bytes", "kind"]) &&
      argument.kind === "buffer" &&
      sameByteArray(argument.bytes, [105, 98, 101, 120]) &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
    );
  }

  function zlibSyncDecoderInput(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return null;
    }
    switch (invocation.exportName) {
      case "brotliDecompressSync":
        return [139, 1, 128, 105, 98, 101, 120, 3];
      case "gunzipSync":
      case "unzipSync":
        return [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ];
      case "inflateRawSync":
        return [203, 76, 74, 173, 0, 0];
      case "inflateSync":
        return [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169];
      default:
        return null;
    }
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Each isolated decoder receives one exact compressed literal whose only
  // accepted result is the original four-byte payload.
  function isReviewedZlibSyncDecoderInvocation(invocation) {
    var input = zlibSyncDecoderInput(invocation);
    if (input === null) return true;
    var descriptor = invocation.sourceDescriptor;
    var argument = invocation.arguments && invocation.arguments[0];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "object-binding",
        "object-source",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "export-property" &&
      sameStringArray(descriptor.access.path, [invocation.exportName]) &&
      exactObjectKeys(invocation.setup, ["kind"]) &&
      invocation.setup.kind === "root-call" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(argument, ["bytes", "kind"]) &&
      argument.kind === "buffer" &&
      sameByteArray(argument.bytes, input) &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
    );
  }

  function zlibCallbackContract(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return null;
    }
    switch (invocation.exportName) {
      case "brotliCompress":
        return {
          input: [105, 98, 101, 120],
          resultContract: "nonempty-byte-view",
        };
      case "brotliDecompress":
        return {
          input: [139, 1, 128, 105, 98, 101, 120, 3],
          resultContract: "exact-ibex-byte-view",
        };
      case "deflate":
      case "deflateRaw":
      case "gzip":
        return {
          input: [105, 98, 101, 120],
          resultContract: "nonempty-byte-view",
        };
      case "gunzip":
      case "unzip":
        return {
          input: [
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55,
            30, 109, 106, 4, 0, 0, 0,
          ],
          resultContract: "exact-ibex-byte-view",
        };
      case "inflate":
        return {
          input: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
          resultContract: "exact-ibex-byte-view",
        };
      case "inflateRaw":
        return {
          input: [203, 76, 74, 173, 0, 0],
          resultContract: "exact-ibex-byte-view",
        };
      default:
        return null;
    }
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // The callback wrapper is credited only after its single deferred delivery,
  // with no error and a codec-specific byte-view result.
  function isReviewedZlibCallbackInvocation(invocation) {
    var contract = zlibCallbackContract(invocation);
    if (contract === null) {
      var arguments_ = invocation && invocation.arguments;
      if (!Array.isArray(arguments_)) return true;
      for (var index = 0; index < arguments_.length; index++) {
        if (arguments_[index] && arguments_[index].kind === "zlib-callback") {
          return false;
        }
      }
      return true;
    }
    var descriptor = invocation.sourceDescriptor;
    var input = invocation.arguments && invocation.arguments[0];
    var callback = invocation.arguments && invocation.arguments[1];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "object-binding",
        "object-source",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "export-property" &&
      sameStringArray(descriptor.access.path, [invocation.exportName]) &&
      exactObjectKeys(invocation.setup, ["kind"]) &&
      invocation.setup.kind === "root-call" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 2 &&
      exactObjectKeys(input, ["bytes", "kind"]) &&
      input.kind === "buffer" &&
      sameByteArray(input.bytes, contract.input) &&
      exactObjectKeys(callback, ["kind", "resultContract"]) &&
      callback.kind === "zlib-callback" &&
      callback.resultContract === contract.resultContract &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "undefined"
    );
  }

  function zlibEndContract(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return null;
    }
    var owner = invocation.exportName.split(".")[0];
    switch (owner) {
      case "BrotliCompress":
      case "Deflate":
      case "DeflateRaw":
      case "Gzip":
        return {
          input: [105, 98, 101, 120],
          outputContract: "nonempty-byte-view",
        };
      case "BrotliDecompress":
        return {
          input: [139, 1, 128, 105, 98, 101, 120, 3],
          outputContract: "exact-ibex-byte-view",
        };
      case "Gunzip":
      case "Unzip":
        return {
          input: [
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55,
            30, 109, 106, 4, 0, 0, 0,
          ],
          outputContract: "exact-ibex-byte-view",
        };
      case "Inflate":
        return {
          input: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
          outputContract: "exact-ibex-byte-view",
        };
      case "InflateRaw":
        return {
          input: [203, 76, 74, 173, 0, 0],
          outputContract: "exact-ibex-byte-view",
        };
      default:
        return null;
    }
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Stream end is credited only after exact output, one finish event, terminal
  // writable state, native cleanup, and event-loop quiescence.
  function isReviewedZlibEndInvocation(invocation) {
    var usesZlibEndSetup =
      invocation &&
      invocation.setup &&
      invocation.setup.kind === "zlib-end-owner";
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib" ||
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith(".end")
    ) {
      return !usesZlibEndSetup;
    }
    var contract = zlibEndContract(invocation);
    if (contract === null) return false;
    var owner = invocation.exportName.split(".")[0];
    var descriptor = invocation.sourceDescriptor;
    var input = invocation.arguments && invocation.arguments[0];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [owner, "prototype", "end"]) &&
      exactObjectKeys(invocation.setup, [
        "kind",
        "outputContract",
        "ownerExportName",
      ]) &&
      invocation.setup.kind === "zlib-end-owner" &&
      invocation.setup.ownerExportName === owner &&
      invocation.setup.outputContract === contract.outputContract &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(input, ["bytes", "kind"]) &&
      input.kind === "buffer" &&
      sameByteArray(input.bytes, contract.input) &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
    );
  }

  function zlibProcessChunkContract(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return null;
    }
    var owner = invocation.exportName.split(".")[0];
    switch (owner) {
      case "BrotliCompress":
      case "Deflate":
      case "DeflateRaw":
      case "Gzip":
        return {
          input: [105, 98, 101, 120],
          outputContract: "nonempty-byte-view",
        };
      case "BrotliDecompress":
        return {
          input: [139, 1, 128, 105, 98, 101, 120, 3],
          outputContract: "exact-ibex-byte-view",
        };
      case "Gunzip":
      case "Unzip":
        return {
          input: [
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55,
            30, 109, 106, 4, 0, 0, 0,
          ],
          outputContract: "exact-ibex-byte-view",
        };
      case "Inflate":
        return {
          input: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
          outputContract: "exact-ibex-byte-view",
        };
      case "InflateRaw":
        return {
          input: [203, 76, 74, 173, 0, 0],
          outputContract: "exact-ibex-byte-view",
        };
      default:
        return null;
    }
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Direct process-chunk evidence is a synchronous one-shot result plus
  // cleanup; it does not claim incremental write or flush state.
  function isReviewedZlibProcessChunkInvocation(invocation) {
    if (
      !invocation ||
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith("._processChunk")
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-process-chunk-owner"
      );
    }
    var contract = zlibProcessChunkContract(invocation);
    if (contract === null) return false;
    var owner = invocation.exportName.split(".")[0];
    var descriptor = invocation.sourceDescriptor;
    var input = invocation.arguments && invocation.arguments[0];
    var flushFlag = invocation.arguments && invocation.arguments[1];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [
        owner,
        "prototype",
        "_processChunk",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "kind",
        "outputContract",
        "ownerExportName",
      ]) &&
      invocation.setup.kind === "zlib-process-chunk-owner" &&
      invocation.setup.ownerExportName === owner &&
      invocation.setup.outputContract === contract.outputContract &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 2 &&
      exactObjectKeys(input, ["bytes", "kind"]) &&
      input.kind === "buffer" &&
      sameByteArray(input.bytes, contract.input) &&
      exactObjectKeys(flushFlag, ["kind", "value"]) &&
      flushFlag.kind === "json" &&
      flushFlag.value === 4 &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
    );
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Incremental write evidence owns the callback and receiver, verifies the
  // exact bounded output after a harness-owned terminal end, destroys the
  // stream, and only then permits event-loop quiescence to complete the
  // fixture.
  function isReviewedZlibWriteInvocation(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-write-owner"
      );
    }
    if (
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith(".write")
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-write-owner"
      );
    }
    var contract = zlibEndContract(invocation);
    if (contract === null) return false;
    var owner = invocation.exportName.split(".")[0];
    var descriptor = invocation.sourceDescriptor;
    var input = invocation.arguments && invocation.arguments[0];
    var callback = invocation.arguments && invocation.arguments[1];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [
        owner,
        "prototype",
        "write",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "kind",
        "outputContract",
        "ownerExportName",
        "terminalMethod",
      ]) &&
      invocation.setup.kind === "zlib-write-owner" &&
      invocation.setup.ownerExportName === owner &&
      invocation.setup.outputContract === contract.outputContract &&
      invocation.setup.terminalMethod === "end" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 2 &&
      exactObjectKeys(input, ["bytes", "kind"]) &&
      input.kind === "buffer" &&
      sameByteArray(input.bytes, contract.input) &&
      exactObjectKeys(callback, ["kind"]) &&
      callback.kind === "zlib-write-callback" &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "boolean"
    );
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // A public flush receipt owns a fresh receiver, delivers exactly one
  // callback through the default full-flush branch, proves the stream remains
  // non-terminal, and destroys the retained codec before quiescence.
  function isReviewedZlibFlushInvocation(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-flush-owner"
      );
    }
    if (
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith(".flush")
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-flush-owner"
      );
    }
    var owner = invocation.exportName.split(".")[0];
    if (
      !{
        BrotliCompress: true,
        BrotliDecompress: true,
        Deflate: true,
        DeflateRaw: true,
        Gunzip: true,
        Gzip: true,
        Inflate: true,
        InflateRaw: true,
        Unzip: true,
        ZstdCompress: true,
        ZstdDecompress: true,
      }[owner]
    ) {
      return false;
    }
    var descriptor = invocation.sourceDescriptor;
    var callback = invocation.arguments && invocation.arguments[0];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [
        owner,
        "prototype",
        "flush",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "callbackPosition",
        "cleanupMethod",
        "flushKind",
        "kind",
        "ownerExportName",
      ]) &&
      invocation.setup.kind === "zlib-flush-owner" &&
      invocation.setup.ownerExportName === owner &&
      invocation.setup.callbackPosition === "first-argument" &&
      invocation.setup.flushKind === "default-full-flush" &&
      invocation.setup.cleanupMethod === "destroy" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(callback, ["kind"]) &&
      callback.kind === "zlib-flush-callback" &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
    );
  }

  function isReviewedZlibParamsInvocation(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-params-owner"
      );
    }
    if (
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith(".params")
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-params-owner"
      );
    }
    var owner = invocation.exportName.split(".")[0];
    if (
      !{
        BrotliCompress: true,
        BrotliDecompress: true,
        Deflate: true,
        DeflateRaw: true,
        Gunzip: true,
        Gzip: true,
        Inflate: true,
        InflateRaw: true,
        Unzip: true,
        ZstdCompress: true,
        ZstdDecompress: true,
      }[owner]
    ) {
      return false;
    }
    var descriptor = invocation.sourceDescriptor;
    var level = invocation.arguments && invocation.arguments[0];
    var strategy = invocation.arguments && invocation.arguments[1];
    var callback = invocation.arguments && invocation.arguments[2];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [
        owner,
        "prototype",
        "params",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "cleanupMethod",
        "kind",
        "level",
        "ownerExportName",
        "strategy",
      ]) &&
      invocation.setup.kind === "zlib-params-owner" &&
      invocation.setup.ownerExportName === owner &&
      invocation.setup.level === 1 &&
      invocation.setup.strategy === 0 &&
      invocation.setup.cleanupMethod === "destroy" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 3 &&
      exactObjectKeys(level, ["kind", "value"]) &&
      level.kind === "json" &&
      level.value === 1 &&
      exactObjectKeys(strategy, ["kind", "value"]) &&
      strategy.kind === "json" &&
      strategy.value === 0 &&
      exactObjectKeys(callback, ["kind"]) &&
      callback.kind === "zlib-params-callback" &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "object"
    );
  }

  function isReviewedZlibTransformInvocation(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-transform-owner"
      );
    }
    if (
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith("._transform")
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-transform-owner"
      );
    }
    var owner = invocation.exportName.split(".")[0];
    var contract = zlibEndContract(invocation);
    if (
      contract === null &&
      (owner === "ZstdCompress" || owner === "ZstdDecompress")
    ) {
      contract = { input: [105, 98, 101, 120] };
    }
    if (contract === null) return false;
    var descriptor = invocation.sourceDescriptor;
    var input = invocation.arguments && invocation.arguments[0];
    var encoding = invocation.arguments && invocation.arguments[1];
    var callback = invocation.arguments && invocation.arguments[2];
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [
        owner,
        "prototype",
        "_transform",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "cleanupMethod",
        "inputLength",
        "kind",
        "ownerExportName",
      ]) &&
      invocation.setup.kind === "zlib-transform-owner" &&
      invocation.setup.ownerExportName === owner &&
      invocation.setup.inputLength === contract.input.length &&
      invocation.setup.cleanupMethod === "destroy" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 3 &&
      exactObjectKeys(input, ["bytes", "kind"]) &&
      input.kind === "buffer" &&
      sameByteArray(input.bytes, contract.input) &&
      exactObjectKeys(encoding, ["kind", "value"]) &&
      encoding.kind === "json" &&
      encoding.value === "buffer" &&
      exactObjectKeys(callback, ["kind"]) &&
      callback.kind === "zlib-transform-callback" &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "undefined"
    );
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Direct finalization evidence first feeds an exact valid input through the
  // same owned receiver, waits for that callback, and only then invokes the
  // selected `_flush`. The callback outcome is exact, including the reviewed
  // ENOSYS refusal for the two no-backend zstd owners.
  function isReviewedZlibDirectFlushInvocation(invocation) {
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_zlib"
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-direct-flush-owner"
      );
    }
    if (
      typeof invocation.exportName !== "string" ||
      !invocation.exportName.endsWith("._flush")
    ) {
      return !(
        invocation &&
        invocation.setup &&
        invocation.setup.kind === "zlib-direct-flush-owner"
      );
    }
    var owner = invocation.exportName.split(".")[0];
    var contract = zlibEndContract(invocation);
    if (
      contract === null &&
      (owner === "ZstdCompress" || owner === "ZstdDecompress")
    ) {
      contract = { input: [105, 98, 101, 120] };
    }
    if (contract === null) return false;
    var descriptor = invocation.sourceDescriptor;
    var callback = invocation.arguments && invocation.arguments[0];
    var expectedErrorCode =
      owner === "ZstdCompress" || owner === "ZstdDecompress"
        ? "ENOSYS"
        : null;
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:zlib" &&
      invocation.templateId === "node-zlib-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/zlib.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        "exported-constructor-inherited-prototype",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:zlib", "zlib"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind === "inherited-prototype-property" &&
      sameStringArray(descriptor.access.path, [
        owner,
        "prototype",
        "_flush",
      ]) &&
      exactObjectKeys(invocation.setup, [
        "cleanupMethod",
        "expectedCallbackErrorCode",
        "kind",
        "ownerExportName",
        "prefillInput",
      ]) &&
      invocation.setup.kind === "zlib-direct-flush-owner" &&
      invocation.setup.ownerExportName === owner &&
      sameByteArray(invocation.setup.prefillInput, contract.input) &&
      invocation.setup.expectedCallbackErrorCode === expectedErrorCode &&
      invocation.setup.cleanupMethod === "destroy" &&
      Array.isArray(invocation.arguments) &&
      invocation.arguments.length === 1 &&
      exactObjectKeys(callback, ["kind"]) &&
      callback.kind === "zlib-direct-flush-callback" &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === "undefined"
    );
  }

  function timerInvocationContract(exportName) {
    var rootContracts = {
      active: ["timer-legacy-root", "active", "record", "undefined"],
      _unrefActive: [
        "timer-legacy-root",
        "_unrefActive",
        "record",
        "undefined",
      ],
      enroll: ["timer-legacy-root", "enroll", "record-delay", "undefined"],
      unenroll: ["timer-legacy-root", "unenroll", "record", "undefined"],
      clearInterval: [
        "timer-clear-root",
        "interval",
        "handle",
        "undefined",
      ],
      clearTimeout: [
        "timer-clear-root",
        "timeout",
        "handle",
        "undefined",
      ],
      setImmediate: [
        "timer-factory-root",
        "immediate",
        "callback",
        "object",
      ],
      setInterval: [
        "timer-factory-root",
        "interval",
        "callback-delay",
        "object",
      ],
      setTimeout: [
        "timer-factory-root",
        "timeout",
        "callback-delay",
        "object",
      ],
    };
    if (own.call(rootContracts, exportName)) {
      return {
        setupKind: rootContracts[exportName][0],
        setupValue: rootContracts[exportName][1],
        argumentsKind: rootContracts[exportName][2],
        resultType: rootContracts[exportName][3],
        prototype: false,
      };
    }
    var parts = typeof exportName === "string" ? exportName.split(".") : [];
    if (parts.length !== 2) return null;
    var owner = parts[0];
    var method = parts[1];
    var resultType = null;
    if (
      (owner === "Immediate" &&
        (method === "close" || method === "ref" || method === "unref")) ||
      (owner === "Timeout" &&
        (method === "close" ||
          method === "ref" ||
          method === "refresh" ||
          method === "unref"))
    ) {
      resultType = "object";
    } else if (
      (owner === "Immediate" || owner === "Timeout") &&
      method === "hasRef"
    ) {
      resultType = "boolean";
    } else if (owner === "Timeout" && method === "_scheduleNative") {
      resultType = "undefined";
    }
    if (resultType === null) return null;
    return {
      setupKind: "timer-owner",
      setupValue: owner,
      argumentsKind: "none",
      resultType: resultType,
      prototype: true,
      preclosed: method === "_scheduleNative",
    };
  }

  function timerArgumentsMatch(arguments_, kind) {
    if (!Array.isArray(arguments_)) return false;
    if (kind === "none") return arguments_.length === 0;
    var first = arguments_[0];
    if (kind === "record" || kind === "record-delay") {
      if (
        !exactObjectKeys(first, ["kind", "name"]) ||
        first.kind !== "setup-value" ||
        first.name !== "timerRecord" ||
        arguments_.length !== (kind === "record-delay" ? 2 : 1)
      ) {
        return false;
      }
    } else if (kind === "handle") {
      return (
        arguments_.length === 1 &&
        exactObjectKeys(first, ["kind", "name"]) &&
        first.kind === "setup-value" &&
        first.name === "timerHandle"
      );
    } else if (kind === "callback" || kind === "callback-delay") {
      if (
        !exactObjectKeys(first, ["kind"]) ||
        first.kind !== "timer-callback" ||
        arguments_.length !== (kind === "callback-delay" ? 2 : 1)
      ) {
        return false;
      }
    } else {
      return false;
    }
    if (kind === "record-delay" || kind === "callback-delay") {
      return (
        exactObjectKeys(arguments_[1], ["kind", "value"]) &&
        arguments_[1].kind === "json" &&
        arguments_[1].value === 60000
      );
    }
    return true;
  }

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // Timer evidence owns every callback and native handle, cancels all pending
  // work, and proves quiescence instead of treating a scheduled return as
  // completion.
  function isReviewedTimerInvocation(invocation) {
    var timerSetup =
      invocation &&
      invocation.setup &&
      (invocation.setup.kind === "timer-clear-root" ||
        invocation.setup.kind === "timer-factory-root" ||
        invocation.setup.kind === "timer-legacy-root" ||
        invocation.setup.kind === "timer-owner");
    if (
      !invocation ||
      !invocation.sourceDescriptor ||
      invocation.sourceDescriptor.sourceKey !== "node_timers"
    ) {
      return !timerSetup;
    }
    // Captured-output timer rows keep their separate exact reviewer. This
    // function owns only the dedicated lifecycle setup vocabulary.
    if (!timerSetup) return true;
    var contract = timerInvocationContract(invocation.exportName);
    if (contract === null) return false;
    var descriptor = invocation.sourceDescriptor;
    var path = contract.prototype
      ? [invocation.exportName.split(".")[0], "prototype", invocation.exportName.split(".")[1]]
      : [invocation.exportName];
    var setupMatches = false;
    if (contract.setupKind === "timer-owner") {
      setupMatches =
        exactObjectKeys(invocation.setup, [
          "kind",
          "ownerExportName",
          "preclosed",
        ]) &&
        invocation.setup.kind === contract.setupKind &&
        invocation.setup.ownerExportName === contract.setupValue &&
        invocation.setup.preclosed === contract.preclosed;
    } else {
      var setupValueKey =
        contract.setupKind === "timer-legacy-root"
          ? "operation"
          : "timerKind";
      setupMatches =
        exactObjectKeys(invocation.setup, ["kind", setupValueKey]) &&
        invocation.setup.kind === contract.setupKind &&
        invocation.setup[setupValueKey] === contract.setupValue;
    }
    return (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
      invocation.kind === "builtin-export-call" &&
      invocation.moduleSpecifier === "node:timers" &&
      invocation.templateId === "node-timers-bounded-v1" &&
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
      descriptor.exportName === invocation.exportName &&
      descriptor.valueShape === "callable" &&
      descriptor.sourceRef ===
        "src/builtins/timers.js#exports:" + invocation.exportName &&
      sameStringArray(descriptor.exportIdioms, [
        contract.prototype
          ? "exported-constructor-prototype"
          : "module-exports-object",
      ]) &&
      sameStringArray(descriptor.moduleSpecifiers, ["node:timers", "timers"]) &&
      exactObjectKeys(descriptor.access, ["kind", "path"]) &&
      descriptor.access.kind ===
        (contract.prototype ? "prototype-property" : "export-property") &&
      sameStringArray(descriptor.access.path, path) &&
      setupMatches &&
      timerArgumentsMatch(invocation.arguments, contract.argumentsKind) &&
      exactObjectKeys(invocation.bodyEntryProof, ["kind", "resultType"]) &&
      invocation.bodyEntryProof.kind ===
        "normal-return-from-source-call" &&
      invocation.bodyEntryProof.resultType === contract.resultType
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
      } else if (
        descriptor.sourceKey === "node_tls" &&
        descriptor.exportName === "SecureContext.context" &&
        access.path[0] === "context" &&
        config.setup &&
        config.setup.kind === "constructed-owner" &&
        config.setup.ownerExportName === "SecureContext" &&
        exactObjectKeys(config.setup, [
          "constructorArguments",
          "kind",
          "ownerExportName",
        ]) &&
        Array.isArray(config.setup.constructorArguments) &&
        config.setup.constructorArguments.length === 0
      ) {
        var secureContextOwner = moduleValue.SecureContext;
        if (typeof secureContextOwner !== "function") {
          return { error: failure("setup-mismatch") };
        }
        instance = Reflect.construct(secureContextOwner, []);
        var secureContextDescriptor = Object.getOwnPropertyDescriptor(
          instance,
          "context",
        );
        if (
          !secureContextDescriptor ||
          secureContextDescriptor.enumerable !== true ||
          secureContextDescriptor.configurable !== false ||
          secureContextDescriptor.writable !== false ||
          secureContextDescriptor.value === null ||
          typeof secureContextDescriptor.value !== "object" ||
          !Object.isFrozen(secureContextDescriptor.value)
        ) {
          return {
            error: failure("shape-mismatch", {
              expectedShape: "own-frozen-opaque-object",
            }),
          };
        }
      } else if (
        descriptor.sourceKey === "node_dgram" &&
        descriptor.exportName === "Socket._closed" &&
        access.path[0] === "_closed" &&
        config.setup &&
        config.setup.kind === "constructed-owner" &&
        config.setup.ownerExportName === "Socket" &&
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
        config.setup.constructorArguments[0].value === "udp4"
      ) {
        var dgramSocketOwner = moduleValue.Socket;
        if (typeof dgramSocketOwner !== "function") {
          return { error: failure("setup-mismatch") };
        }
        instance = Reflect.construct(dgramSocketOwner, ["udp4"]);
        var dgramClosedDescriptor = Object.getOwnPropertyDescriptor(
          instance,
          "_closed",
        );
        if (
          !dgramClosedDescriptor ||
          dgramClosedDescriptor.enumerable !== false ||
          dgramClosedDescriptor.configurable !== false ||
          typeof dgramClosedDescriptor.get !== "function" ||
          typeof dgramClosedDescriptor.set !== "function"
        ) {
          return {
            error: failure("shape-mismatch", {
              expectedShape: "own-private-state-accessor",
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
    if (argument.kind === "timer-callback") {
      if (!bindings.timerLifecycleState) {
        throw new TypeError("missing authored timer lifecycle state");
      }
      return function () {
        bindings.timerLifecycleState.callbackCalls++;
      };
    }
    if (argument.kind === "zlib-write-callback") {
      if (!bindings.zlibWriteLifecycleState) {
        throw new TypeError("missing authored zlib write lifecycle state");
      }
      return function (error) {
        bindings.zlibWriteLifecycleState.callbackCalls++;
        bindings.zlibWriteLifecycleState.callbackError = error || null;
        bindings.zlibWriteLifecycleState.finish();
      };
    }
    if (argument.kind === "zlib-flush-callback") {
      if (!bindings.zlibFlushLifecycleState) {
        throw new TypeError("missing authored zlib flush lifecycle state");
      }
      return function (error) {
        bindings.zlibFlushLifecycleState.callbackCalls++;
        bindings.zlibFlushLifecycleState.callbackError = error || null;
        bindings.zlibFlushLifecycleState.retire();
      };
    }
    if (argument.kind === "zlib-params-callback") {
      if (!bindings.zlibParamsLifecycleState) {
        throw new TypeError("missing authored zlib params lifecycle state");
      }
      return function (error) {
        bindings.zlibParamsLifecycleState.callbackCalls++;
        bindings.zlibParamsLifecycleState.callbackError = error || null;
        bindings.zlibParamsLifecycleState.retire();
      };
    }
    if (argument.kind === "zlib-transform-callback") {
      if (!bindings.zlibTransformLifecycleState) {
        throw new TypeError("missing authored zlib transform lifecycle state");
      }
      return function (error) {
        bindings.zlibTransformLifecycleState.callbackCalls++;
        bindings.zlibTransformLifecycleState.callbackError = error || null;
        bindings.zlibTransformLifecycleState.retire();
      };
    }
    if (argument.kind === "zlib-direct-flush-callback") {
      if (!bindings.zlibDirectFlushLifecycleState) {
        throw new TypeError(
          "missing authored direct zlib flush lifecycle state",
        );
      }
      return function (error) {
        bindings.zlibDirectFlushLifecycleState.callbackCalls++;
        bindings.zlibDirectFlushLifecycleState.callbackError =
          error || null;
        bindings.zlibDirectFlushLifecycleState.retire();
      };
    }
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
    if (argument.kind === "zlib-callback") {
      if (
        own.call(bindings, "zlibCallbackState") ||
        !own.call(bindings, "zlibCallbackContract") ||
        argument.resultContract !==
          bindings.zlibCallbackContract.resultContract
      ) {
        throw new TypeError("invalid authored zlib callback");
      }
      var resolveCallback;
      var state = {
        calls: 0,
        outputVerified: false,
        promise: new Promise(function (resolve) {
          resolveCallback = resolve;
        }),
      };
      bindings.zlibCallbackState = state;
      return function (error, output) {
        state.calls++;
        state.outputVerified =
          state.calls === 1 &&
          error === null &&
          (argument.resultContract === "nonempty-byte-view"
            ? output !== null &&
              typeof output === "object" &&
              ArrayBuffer.isView(output) &&
              typeof output.byteLength === "number" &&
              output.byteLength > 0
            : argument.resultContract === "exact-ibex-byte-view" &&
              sameByteView(output, [105, 98, 101, 120]));
        resolveCallback(state.outputVerified);
      };
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
    var netLifecycleVerified = false;
    var netLifecyclePromise = null;
    var tlsServerLifecycleVerified = false;
    var tlsServerLifecyclePromise = null;
    var zlibSyncEncoderOutputVerified = false;
    var zlibSyncDecoderOutputVerified = false;
    var zlibCallbackOutputVerified = false;
    var zlibCallbackPromise = null;
    var zlibEndLifecycleVerified = false;
    var zlibEndLifecyclePromise = null;
    var zlibProcessChunkOutputVerified = false;
    var zlibFlushLifecycleVerified = false;
    var zlibFlushLifecyclePromise = null;
    var zlibParamsLifecycleVerified = false;
    var zlibParamsLifecyclePromise = null;
    var zlibTransformLifecycleVerified = false;
    var zlibTransformLifecyclePromise = null;
    var zlibDirectFlushLifecycleVerified = false;
    var zlibDirectFlushLifecyclePromise = null;
    var zlibDirectFlushDispatchPromise = null;
    var zlibWriteLifecycleVerified = false;
    var zlibWriteLifecyclePromise = null;
    var timerLifecycleState = null;
    var timerLifecycleVerified = false;
    var readlineLifecycleState = null;
    if (
      !isReviewedBoundedHttpInvocation(config) ||
      !isReviewedIdleNetTerminalInvocation(config) ||
      !isReviewedIdleTlsSocketInvocation(config) ||
      !isReviewedIdleTlsServerInvocation(config) ||
      !isReviewedIdleDgramInvocation(config) ||
      !isReviewedZlibSyncEncoderInvocation(config) ||
      !isReviewedZlibSyncDecoderInvocation(config) ||
      !isReviewedZlibCallbackInvocation(config) ||
      !isReviewedZlibEndInvocation(config) ||
      !isReviewedZlibProcessChunkInvocation(config) ||
      !isReviewedZlibFlushInvocation(config) ||
      !isReviewedZlibParamsInvocation(config) ||
      !isReviewedZlibTransformInvocation(config) ||
      !isReviewedZlibDirectFlushInvocation(config) ||
      !isReviewedZlibWriteInvocation(config) ||
      !isReviewedTimerInvocation(config) ||
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
    if (
      setup.kind === "root-call" ||
      setup.kind === "tls-server-root-call"
    ) {
      receiver = moduleValue;
      dispatchKind = "call";
    } else if (
      setup.kind === "timer-clear-root" ||
      setup.kind === "timer-factory-root" ||
      setup.kind === "timer-legacy-root"
    ) {
      timerLifecycleState = {
        callbackCalls: 0,
        setupHandles: [],
        timerRecord: null,
      };
      bindings.timerLifecycleState = timerLifecycleState;
      var trackedTimerCallback = function () {
        timerLifecycleState.callbackCalls++;
      };
      if (setup.kind === "timer-clear-root") {
        var setupTimerHandle = Reflect.construct(moduleValue.Timeout, [
          trackedTimerCallback,
          60000,
          [],
          setup.timerKind === "interval",
        ]);
        timerLifecycleState.setupHandles.push(setupTimerHandle);
        bindings.timerHandle = setupTimerHandle;
      } else if (setup.kind === "timer-legacy-root") {
        var timerRecord = {
          _idleTimeout: 60000,
          _onTimeout: trackedTimerCallback,
        };
        if (setup.operation === "unenroll") {
          timerRecord._exactActiveHandle = globalThis.setTimeout(
            trackedTimerCallback,
            60000,
          );
          timerRecord._exactUnrefHandle = globalThis.setTimeout(
            trackedTimerCallback,
            60000,
          );
          timerLifecycleState.setupHandles.push(
            timerRecord._exactActiveHandle,
            timerRecord._exactUnrefHandle,
          );
        }
        timerLifecycleState.timerRecord = timerRecord;
        bindings.timerRecord = timerRecord;
      }
      receiver = moduleValue;
      dispatchKind = "call";
    } else if (setup.kind === "timer-owner") {
      timerLifecycleState = {
        callbackCalls: 0,
        setupHandles: [],
        timerRecord: null,
      };
      bindings.timerLifecycleState = timerLifecycleState;
      var timerOwner = moduleValue[setup.ownerExportName];
      if (typeof timerOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var ownerTimerCallback = function () {
        timerLifecycleState.callbackCalls++;
      };
      receiver =
        setup.ownerExportName === "Immediate"
          ? Reflect.construct(timerOwner, [ownerTimerCallback, []])
          : Reflect.construct(timerOwner, [
              ownerTimerCallback,
              60000,
              [],
              false,
            ]);
      if (
        !receiver ||
        typeof receiver.close !== "function" ||
        (setup.preclosed && receiver.close() !== receiver)
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      dispatchKind = "prototype-call";
    } else if (
      setup.kind === "construct-target" ||
      setup.kind === "tls-server-construct-target"
    ) {
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
    } else if (setup.kind === "net-terminal-owner") {
      var netOwner = moduleValue[setup.ownerExportName];
      if (typeof netOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(netOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      netLifecyclePromise = new Promise(function (resolve) {
        var closeEvents = 0;
        function onClose() {
          closeEvents++;
          if (closeEvents !== 1) return;
          setTimeout(function () {
            receiver.removeListener("close", onClose);
            var terminalState =
              setup.ownerExportName === "Server"
                ? receiver.listening === false && receiver._handle === null
                : receiver.destroyed === true &&
                  receiver._handle === null &&
                  receiver.readyState === "closed";
            netLifecycleVerified = closeEvents === 1 && terminalState;
            cleanupPerformed = netLifecycleVerified;
            resolve(netLifecycleVerified);
          }, 0);
        }
        receiver.on("close", onClose);
      });
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
    } else if (setup.kind === "zlib-end-owner") {
      var zlibEndOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibEndOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibEndOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function" ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      zlibEndLifecyclePromise = new Promise(function (resolve) {
        var finishEvents = 0;
        var outputChunks = [];
        var failed = false;
        function onData(chunk) {
          if (!chunk || !ArrayBuffer.isView(chunk)) {
            failed = true;
            return;
          }
          outputChunks.push(
            new Uint8Array(
              chunk.buffer,
              chunk.byteOffset,
              chunk.byteLength,
            ),
          );
        }
        function onError() {
          failed = true;
          resolve(false);
        }
        function onFinish() {
          finishEvents++;
          if (finishEvents !== 1) return;
          setTimeout(function () {
            receiver.removeListener("data", onData);
            receiver.removeListener("error", onError);
            receiver.removeListener("finish", onFinish);
            var totalLength = 0;
            for (var index = 0; index < outputChunks.length; index++) {
              totalLength += outputChunks[index].byteLength;
            }
            var output = new Uint8Array(totalLength);
            var offset = 0;
            for (
              var chunkIndex = 0;
              chunkIndex < outputChunks.length;
              chunkIndex++
            ) {
              output.set(outputChunks[chunkIndex], offset);
              offset += outputChunks[chunkIndex].byteLength;
            }
            try {
              receiver._closeNativeStream();
              cleanupPerformed = true;
            } catch (_cleanupError) {
              failed = true;
            }
            var outputVerified =
              setup.outputContract === "nonempty-byte-view"
                ? output.byteLength > 0
                : sameByteView(output, [105, 98, 101, 120]);
            zlibEndLifecycleVerified =
              !failed &&
              finishEvents === 1 &&
              receiver._flushed === true &&
              receiver.writableEnded === true &&
              outputVerified &&
              cleanupPerformed;
            resolve(zlibEndLifecycleVerified);
          }, 0);
        }
        receiver.on("data", onData);
        receiver.on("error", onError);
        receiver.on("finish", onFinish);
      });
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-process-chunk-owner") {
      var zlibProcessChunkOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibProcessChunkOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibProcessChunkOwner, []);
      if (
        !receiver ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-write-owner") {
      var zlibWriteOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibWriteOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibWriteOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function" ||
        typeof receiver.end !== "function" ||
        typeof receiver.destroy !== "function" ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var zlibWriteLifecycleState = {
        callbackCalls: 0,
        callbackError: null,
        streamError: null,
        outputChunks: [],
        finishScheduled: false,
        finishEvents: 0,
        retireScheduled: false,
        finish: null,
      };
      bindings.zlibWriteLifecycleState = zlibWriteLifecycleState;
      zlibWriteLifecyclePromise = new Promise(function (resolve) {
        function onData(chunk) {
          if (!chunk || !ArrayBuffer.isView(chunk)) {
            zlibWriteLifecycleState.streamError = new TypeError(
              "zlib write emitted a non-byte chunk",
            );
            return;
          }
          zlibWriteLifecycleState.outputChunks.push(
            new Uint8Array(
              chunk.buffer,
              chunk.byteOffset,
              chunk.byteLength,
            ),
          );
        }
        function onError(error) {
          zlibWriteLifecycleState.streamError =
            error || new Error("zlib write emitted an unknown error");
          retire();
        }
        function onFinish() {
          zlibWriteLifecycleState.finishEvents++;
          retire();
        }
        function retire() {
          if (zlibWriteLifecycleState.retireScheduled) return;
          zlibWriteLifecycleState.retireScheduled = true;
          receiver.destroy(null, function (destroyError) {
            setTimeout(function () {
              receiver.removeListener("data", onData);
              receiver.removeListener("error", onError);
              receiver.removeListener("finish", onFinish);
              var totalLength = 0;
              for (
                var index = 0;
                index < zlibWriteLifecycleState.outputChunks.length;
                index++
              ) {
                totalLength +=
                  zlibWriteLifecycleState.outputChunks[index].byteLength;
              }
              var output = new Uint8Array(totalLength);
              var offset = 0;
              for (
                var chunkIndex = 0;
                chunkIndex < zlibWriteLifecycleState.outputChunks.length;
                chunkIndex++
              ) {
                output.set(
                  zlibWriteLifecycleState.outputChunks[chunkIndex],
                  offset,
                );
                offset +=
                  zlibWriteLifecycleState.outputChunks[chunkIndex].byteLength;
              }
              cleanupPerformed =
                !destroyError &&
                receiver.destroyed === true &&
                receiver._handle === null;
              var outputVerified =
                setup.outputContract === "nonempty-byte-view"
                  ? output.byteLength > 0
                  : sameByteView(output, [105, 98, 101, 120]);
              zlibWriteLifecycleState.outputLength = output.byteLength;
              zlibWriteLifecycleState.outputVerified = outputVerified;
              zlibWriteLifecycleState.receiverDestroyed =
                receiver.destroyed === true;
              zlibWriteLifecycleState.nativeHandleClosed =
                receiver._handle === null;
              zlibWriteLifecycleState.streamFlushed =
                receiver._flushed === true;
              zlibWriteLifecycleState.writableEnded =
                receiver.writableEnded === true;
              zlibWriteLifecycleVerified =
                zlibWriteLifecycleState.callbackCalls === 1 &&
                zlibWriteLifecycleState.callbackError === null &&
                zlibWriteLifecycleState.streamError === null &&
                zlibWriteLifecycleState.finishEvents === 1 &&
                zlibWriteLifecycleState.streamFlushed &&
                zlibWriteLifecycleState.writableEnded &&
                outputVerified &&
                cleanupPerformed;
              resolve(zlibWriteLifecycleVerified);
            }, 0);
          });
        }
        zlibWriteLifecycleState.finish = function () {
          if (zlibWriteLifecycleState.finishScheduled) return;
          zlibWriteLifecycleState.finishScheduled = true;
          setTimeout(function () {
            try {
              receiver.end();
            } catch (error) {
              zlibWriteLifecycleState.streamError = error;
              retire();
            }
          }, 0);
        };
        receiver.on("data", onData);
        receiver.on("error", onError);
        receiver.on("finish", onFinish);
      });
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-flush-owner") {
      var zlibFlushOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibFlushOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibFlushOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function" ||
        typeof receiver.destroy !== "function" ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var zlibFlushLifecycleState = {
        callbackCalls: 0,
        callbackError: null,
        streamError: null,
        outputChunks: 0,
        retireScheduled: false,
        receiverNonTerminalBeforeCleanup: false,
        retire: null,
      };
      bindings.zlibFlushLifecycleState = zlibFlushLifecycleState;
      zlibFlushLifecyclePromise = new Promise(function (resolve) {
        function onData(chunk) {
          if (!chunk || !ArrayBuffer.isView(chunk)) {
            zlibFlushLifecycleState.streamError = new TypeError(
              "zlib flush emitted a non-byte chunk",
            );
            return;
          }
          zlibFlushLifecycleState.outputChunks++;
        }
        function onError(error) {
          zlibFlushLifecycleState.streamError =
            error || new Error("zlib flush emitted an unknown error");
          retire();
        }
        function retire() {
          if (zlibFlushLifecycleState.retireScheduled) return;
          zlibFlushLifecycleState.retireScheduled = true;
          zlibFlushLifecycleState.receiverNonTerminalBeforeCleanup =
            receiver._flushed === false &&
            receiver.writableEnded === false;
          receiver.destroy(null, function (destroyError) {
            setTimeout(function () {
              receiver.removeListener("data", onData);
              receiver.removeListener("error", onError);
              cleanupPerformed =
                !destroyError &&
                receiver.destroyed === true &&
                receiver._handle === null;
              zlibFlushLifecycleState.receiverDestroyed =
                receiver.destroyed === true;
              zlibFlushLifecycleState.nativeHandleClosed =
                receiver._handle === null;
              zlibFlushLifecycleVerified =
                zlibFlushLifecycleState.callbackCalls === 1 &&
                zlibFlushLifecycleState.callbackError === null &&
                zlibFlushLifecycleState.streamError === null &&
                zlibFlushLifecycleState.receiverNonTerminalBeforeCleanup &&
                cleanupPerformed;
              resolve(zlibFlushLifecycleVerified);
            }, 0);
          });
        }
        zlibFlushLifecycleState.retire = retire;
        receiver.on("data", onData);
        receiver.on("error", onError);
      });
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-params-owner") {
      var zlibParamsOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibParamsOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibParamsOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function" ||
        typeof receiver.destroy !== "function" ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var zlibParamsLifecycleState = {
        callbackCalls: 0,
        callbackError: null,
        streamError: null,
        outputChunks: 0,
        retireScheduled: false,
        selectedStateBeforeCleanup: false,
        receiverNonTerminalBeforeCleanup: false,
        retire: null,
      };
      bindings.zlibParamsLifecycleState = zlibParamsLifecycleState;
      zlibParamsLifecyclePromise = new Promise(function (resolve) {
        function onData(chunk) {
          if (!chunk || !ArrayBuffer.isView(chunk)) {
            zlibParamsLifecycleState.streamError = new TypeError(
              "zlib params emitted a non-byte chunk",
            );
            return;
          }
          zlibParamsLifecycleState.outputChunks++;
        }
        function onError(error) {
          zlibParamsLifecycleState.streamError =
            error || new Error("zlib params emitted an unknown error");
          retire();
        }
        function retire() {
          if (zlibParamsLifecycleState.retireScheduled) return;
          zlibParamsLifecycleState.retireScheduled = true;
          zlibParamsLifecycleState.selectedStateBeforeCleanup =
            receiver._level === setup.level &&
            receiver._strategy === setup.strategy;
          zlibParamsLifecycleState.receiverNonTerminalBeforeCleanup =
            receiver._flushed === false &&
            receiver.writableEnded === false;
          receiver.destroy(null, function (destroyError) {
            setTimeout(function () {
              receiver.removeListener("data", onData);
              receiver.removeListener("error", onError);
              cleanupPerformed =
                !destroyError &&
                receiver.destroyed === true &&
                receiver._handle === null;
              zlibParamsLifecycleState.receiverDestroyed =
                receiver.destroyed === true;
              zlibParamsLifecycleState.nativeHandleClosed =
                receiver._handle === null;
              zlibParamsLifecycleVerified =
                zlibParamsLifecycleState.callbackCalls === 1 &&
                zlibParamsLifecycleState.callbackError === null &&
                zlibParamsLifecycleState.streamError === null &&
                zlibParamsLifecycleState.selectedStateBeforeCleanup &&
                zlibParamsLifecycleState.receiverNonTerminalBeforeCleanup &&
                cleanupPerformed;
              resolve(zlibParamsLifecycleVerified);
            }, 0);
          });
        }
        zlibParamsLifecycleState.retire = retire;
        receiver.on("data", onData);
        receiver.on("error", onError);
      });
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-transform-owner") {
      var zlibTransformOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibTransformOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibTransformOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function" ||
        typeof receiver.destroy !== "function" ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var zlibTransformLifecycleState = {
        callbackCalls: 0,
        callbackError: null,
        streamError: null,
        outputChunks: 0,
        retireScheduled: false,
        acceptedInputBeforeCleanup: false,
        receiverNonTerminalBeforeCleanup: false,
        retire: null,
      };
      bindings.zlibTransformLifecycleState = zlibTransformLifecycleState;
      zlibTransformLifecyclePromise = new Promise(function (resolve) {
        function onData(chunk) {
          if (!chunk || !ArrayBuffer.isView(chunk)) {
            zlibTransformLifecycleState.streamError = new TypeError(
              "zlib transform emitted a non-byte chunk",
            );
            return;
          }
          zlibTransformLifecycleState.outputChunks++;
        }
        function onError(error) {
          zlibTransformLifecycleState.streamError =
            error || new Error("zlib transform emitted an unknown error");
          retire();
        }
        function retire() {
          if (zlibTransformLifecycleState.retireScheduled) return;
          zlibTransformLifecycleState.retireScheduled = true;
          zlibTransformLifecycleState.acceptedInputBeforeCleanup =
            receiver._bytesWritten === setup.inputLength &&
            receiver.bytesWritten === setup.inputLength;
          zlibTransformLifecycleState.receiverNonTerminalBeforeCleanup =
            receiver._flushed === false &&
            receiver.writableEnded === false;
          receiver.destroy(null, function (destroyError) {
            setTimeout(function () {
              receiver.removeListener("data", onData);
              receiver.removeListener("error", onError);
              cleanupPerformed =
                !destroyError &&
                receiver.destroyed === true &&
                receiver._handle === null;
              zlibTransformLifecycleState.receiverDestroyed =
                receiver.destroyed === true;
              zlibTransformLifecycleState.nativeHandleClosed =
                receiver._handle === null;
              zlibTransformLifecycleVerified =
                zlibTransformLifecycleState.callbackCalls === 1 &&
                zlibTransformLifecycleState.callbackError === null &&
                zlibTransformLifecycleState.streamError === null &&
                zlibTransformLifecycleState.acceptedInputBeforeCleanup &&
                zlibTransformLifecycleState.receiverNonTerminalBeforeCleanup &&
                cleanupPerformed;
              resolve(zlibTransformLifecycleVerified);
            }, 0);
          });
        }
        zlibTransformLifecycleState.retire = retire;
        receiver.on("data", onData);
        receiver.on("error", onError);
      });
      dispatchKind = "prototype-call";
    } else if (setup.kind === "zlib-direct-flush-owner") {
      var zlibDirectFlushOwner = moduleValue[setup.ownerExportName];
      if (typeof zlibDirectFlushOwner !== "function") {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      receiver = Reflect.construct(zlibDirectFlushOwner, []);
      if (
        !receiver ||
        typeof receiver.on !== "function" ||
        typeof receiver.removeListener !== "function" ||
        typeof receiver._transform !== "function" ||
        typeof receiver.destroy !== "function" ||
        typeof receiver._closeNativeStream !== "function"
      ) {
        return failure("setup-mismatch", {
          setupKind: setup.kind,
          ownerExportName: setup.ownerExportName,
        });
      }
      var zlibDirectFlushLifecycleState = {
        prefillCallbackCalls: 0,
        prefillCallbackError: null,
        callbackCalls: 0,
        callbackError: null,
        streamError: null,
        outputChunks: 0,
        retireScheduled: false,
        acceptedInputBeforeCleanup: false,
        flushedBeforeCleanup: false,
        receiverNonTerminalBeforeCleanup: false,
        retire: null,
      };
      bindings.zlibDirectFlushLifecycleState =
        zlibDirectFlushLifecycleState;
      zlibDirectFlushLifecyclePromise = new Promise(function (resolve) {
        function onData(chunk) {
          if (!chunk || !ArrayBuffer.isView(chunk)) {
            zlibDirectFlushLifecycleState.streamError = new TypeError(
              "direct zlib flush emitted a non-byte chunk",
            );
            return;
          }
          zlibDirectFlushLifecycleState.outputChunks++;
        }
        function onError(error) {
          zlibDirectFlushLifecycleState.streamError =
            error ||
            new Error("direct zlib flush emitted an unknown error");
          retire();
        }
        function retire() {
          if (zlibDirectFlushLifecycleState.retireScheduled) return;
          zlibDirectFlushLifecycleState.retireScheduled = true;
          zlibDirectFlushLifecycleState.acceptedInputBeforeCleanup =
            receiver._bytesWritten === setup.prefillInput.length &&
            receiver.bytesWritten === setup.prefillInput.length;
          zlibDirectFlushLifecycleState.flushedBeforeCleanup =
            receiver._flushed === true;
          zlibDirectFlushLifecycleState.receiverNonTerminalBeforeCleanup =
            receiver.writableEnded === false;
          receiver.destroy(null, function (destroyError) {
            setTimeout(function () {
              receiver.removeListener("data", onData);
              receiver.removeListener("error", onError);
              cleanupPerformed =
                !destroyError &&
                receiver.destroyed === true &&
                receiver._handle === null;
              zlibDirectFlushLifecycleState.receiverDestroyed =
                receiver.destroyed === true;
              zlibDirectFlushLifecycleState.nativeHandleClosed =
                receiver._handle === null;
              var callbackErrorCode =
                zlibDirectFlushLifecycleState.callbackError &&
                typeof zlibDirectFlushLifecycleState.callbackError.code ===
                  "string"
                  ? zlibDirectFlushLifecycleState.callbackError.code
                  : null;
              zlibDirectFlushLifecycleVerified =
                zlibDirectFlushLifecycleState.prefillCallbackCalls === 1 &&
                zlibDirectFlushLifecycleState.prefillCallbackError === null &&
                zlibDirectFlushLifecycleState.callbackCalls === 1 &&
                callbackErrorCode ===
                  setup.expectedCallbackErrorCode &&
                zlibDirectFlushLifecycleState.streamError === null &&
                zlibDirectFlushLifecycleState.acceptedInputBeforeCleanup &&
                zlibDirectFlushLifecycleState.flushedBeforeCleanup &&
                zlibDirectFlushLifecycleState
                  .receiverNonTerminalBeforeCleanup &&
                cleanupPerformed;
              resolve(zlibDirectFlushLifecycleVerified);
            }, 0);
          });
        }
        zlibDirectFlushLifecycleState.retire = retire;
        receiver.on("data", onData);
        receiver.on("error", onError);
      });
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

    var reviewedZlibCallbackContract = zlibCallbackContract(config);
    if (reviewedZlibCallbackContract !== null) {
      bindings.zlibCallbackContract = reviewedZlibCallbackContract;
    }
    var callArguments = materializeList(
      config.arguments,
      moduleValue,
      bindings,
    );
    if (own.call(bindings, "zlibCallbackState")) {
      zlibCallbackPromise = bindings.zlibCallbackState.promise;
    }
    function finishTimerLifecycle() {
      if (!timerLifecycleState) return;
      var targetEffectVerified = false;
      var cleanupVerified = false;
      try {
        if (setup.kind === "timer-clear-root") {
          var clearedHandle = timerLifecycleState.setupHandles[0];
          targetEffectVerified =
            result === undefined &&
            clearedHandle &&
            typeof clearedHandle === "object" &&
            clearedHandle._destroyed === true;
          if (
            clearedHandle &&
            typeof clearedHandle === "object" &&
            typeof clearedHandle.close === "function"
          ) {
            clearedHandle.close();
          } else if (clearedHandle !== undefined) {
            globalThis.clearTimeout(clearedHandle);
          }
          cleanupVerified =
            !clearedHandle ||
            typeof clearedHandle !== "object" ||
            clearedHandle._destroyed === true;
        } else if (setup.kind === "timer-factory-root") {
          targetEffectVerified =
            result &&
            typeof result === "object" &&
            typeof result.close === "function" &&
            result._destroyed === false;
          if (result && typeof result.close === "function") {
            result.close();
          }
          cleanupVerified =
            result &&
            typeof result === "object" &&
            result._destroyed === true;
        } else if (setup.kind === "timer-legacy-root") {
          var record = timerLifecycleState.timerRecord;
          if (setup.operation === "active") {
            targetEffectVerified =
              result === undefined &&
              record._exactActiveHandle != null;
            if (
              record._exactActiveHandle &&
              typeof record._exactActiveHandle.close === "function"
            ) {
              record._exactActiveHandle.close();
            } else if (record._exactActiveHandle != null) {
              globalThis.clearTimeout(record._exactActiveHandle);
            }
            record._exactActiveHandle = null;
            record._idleTimeout = -1;
          } else if (setup.operation === "_unrefActive") {
            targetEffectVerified =
              result === undefined &&
              record._exactUnrefHandle != null &&
              (typeof record._exactUnrefHandle !== "object" ||
                (typeof record._exactUnrefHandle.hasRef === "function" &&
                  record._exactUnrefHandle.hasRef() === false));
            if (
              record._exactUnrefHandle &&
              typeof record._exactUnrefHandle.close === "function"
            ) {
              record._exactUnrefHandle.close();
            } else if (record._exactUnrefHandle != null) {
              globalThis.clearTimeout(record._exactUnrefHandle);
            }
            record._exactUnrefHandle = null;
            record._idleTimeout = -1;
          } else if (setup.operation === "enroll") {
            targetEffectVerified =
              result === undefined && record._idleTimeout === 60000;
            record._idleTimeout = -1;
          } else if (setup.operation === "unenroll") {
            targetEffectVerified =
              result === undefined &&
              record._idleTimeout === -1 &&
              record._exactActiveHandle === null &&
              record._exactUnrefHandle === null &&
              timerLifecycleState.setupHandles.every(function (handle) {
                return (
                  handle != null &&
                  (typeof handle !== "object" ||
                    handle._destroyed === true)
                );
              });
          }
          cleanupVerified =
            record._idleTimeout === -1 &&
            record._exactActiveHandle == null &&
            record._exactUnrefHandle == null;
        } else if (setup.kind === "timer-owner") {
          var timerMethod = config.exportName.split(".")[1];
          if (timerMethod === "hasRef") {
            targetEffectVerified = result === true;
          } else if (timerMethod === "unref") {
            targetEffectVerified =
              result === receiver && receiver._refed === false;
          } else if (timerMethod === "_scheduleNative") {
            targetEffectVerified =
              result === undefined &&
              receiver._nativeHandle != null &&
              receiver._destroyed === true;
          } else if (timerMethod === "close") {
            targetEffectVerified =
              result === receiver && receiver._destroyed === true;
          } else {
            targetEffectVerified =
              result === receiver &&
              receiver._refed === true &&
              receiver._destroyed === false;
          }
          receiver.close();
          cleanupVerified = receiver._destroyed === true;
        }
      } catch (_timerCleanupError) {
        cleanupVerified = false;
      }
      cleanupPerformed = cleanupVerified;
      timerLifecycleVerified =
        targetEffectVerified &&
        cleanupVerified &&
        timerLifecycleState.callbackCalls === 0;
    }
    try {
      if (setup.kind === "zlib-direct-flush-owner") {
        zlibDirectFlushDispatchPromise = new Promise(function (resolve) {
          var prefillSettled = false;
          function failPrefill(error) {
            zlibDirectFlushLifecycleState.streamError =
              error || new Error("direct zlib flush prefill failed");
            zlibDirectFlushLifecycleState.retire();
            resolve({ error: zlibDirectFlushLifecycleState.streamError });
          }
          try {
            receiver._transform(
              Buffer.from(setup.prefillInput),
              "buffer",
              function (error) {
                zlibDirectFlushLifecycleState.prefillCallbackCalls++;
                zlibDirectFlushLifecycleState.prefillCallbackError =
                  error || null;
                if (prefillSettled) return;
                prefillSettled = true;
                if (error) {
                  failPrefill(error);
                  return;
                }
                try {
                  sourceOperationAttempted = true;
                  resolve({
                    result: Reflect.apply(
                      target,
                      receiver,
                      callArguments,
                    ),
                  });
                } catch (sourceError) {
                  zlibDirectFlushLifecycleState.streamError = sourceError;
                  zlibDirectFlushLifecycleState.retire();
                  resolve({ error: sourceError });
                }
              },
            );
          } catch (prefillError) {
            prefillSettled = true;
            failPrefill(prefillError);
          }
        });
      } else {
        sourceOperationAttempted = true;
        if (dispatchKind === "construct") {
          result = Reflect.construct(target, callArguments);
        } else {
          result = Reflect.apply(target, receiver, callArguments);
        }
      }
      if (isZlibSyncEncoderInvocation(config)) {
        zlibSyncEncoderOutputVerified =
          result !== null &&
          typeof result === "object" &&
          ArrayBuffer.isView(result) &&
          typeof result.byteLength === "number" &&
          result.byteLength > 0;
        if (!zlibSyncEncoderOutputVerified) {
          return failure("result-shape-mismatch", {
            expectedShape: "nonempty-byte-view",
          });
        }
      }
      var zlibSyncDecoderInputBytes = zlibSyncDecoderInput(config);
      if (zlibSyncDecoderInputBytes !== null) {
        zlibSyncDecoderOutputVerified = sameByteView(
          result,
          [105, 98, 101, 120],
        );
        if (!zlibSyncDecoderOutputVerified) {
          return failure("result-shape-mismatch", {
            expectedShape: "exact-byte-view",
          });
        }
      }
      var zlibProcessChunkOutputContract =
        setup.kind === "zlib-process-chunk-owner"
          ? setup.outputContract
          : null;
      if (zlibProcessChunkOutputContract !== null) {
        zlibProcessChunkOutputVerified =
          zlibProcessChunkOutputContract === "nonempty-byte-view"
            ? result !== null &&
              typeof result === "object" &&
              ArrayBuffer.isView(result) &&
              result.byteLength > 0
            : sameByteView(result, [105, 98, 101, 120]);
        if (!zlibProcessChunkOutputVerified) {
          return failure("result-shape-mismatch", {
            expectedShape: zlibProcessChunkOutputContract,
          });
        }
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
      if (
        setup.kind === "tls-server-construct-target" ||
        setup.kind === "tls-server-root-call"
      ) {
        var tlsServer = result;
        if (
          !tlsServer ||
          typeof tlsServer.once !== "function" ||
          typeof tlsServer.close !== "function" ||
          typeof tlsServer.address !== "function"
        ) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
          });
        }
        tlsServerLifecyclePromise = new Promise(function (resolve) {
          var closeEvents = 0;
          tlsServer.once("close", function () {
            closeEvents++;
            setTimeout(function () {
              var retirementError = null;
              try {
                tlsServer.address();
              } catch (error) {
                retirementError = error;
              }
              tlsServerLifecycleVerified =
                closeEvents === 1 &&
                retirementError !== null &&
                retirementError.code === "ERR_TLS_SERVER_CLOSED";
              cleanupPerformed = tlsServerLifecycleVerified;
              resolve(tlsServerLifecycleVerified);
            }, 0);
          });
          tlsServer.close();
        });
      }
    } finally {
      finishTimerLifecycle();
      if (
        (setup.kind === "zlib-owner" ||
          setup.kind === "zlib-process-chunk-owner") &&
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
        if (setup.kind === "zlib-write-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.zlibWriteLifecycleVerified =
            zlibWriteLifecycleVerified;
        }
        if (setup.kind === "zlib-flush-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.zlibFlushLifecycleVerified =
            zlibFlushLifecycleVerified;
        }
        if (setup.kind === "zlib-params-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.zlibParamsLifecycleVerified =
            zlibParamsLifecycleVerified;
        }
        if (setup.kind === "zlib-transform-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.zlibTransformLifecycleVerified =
            zlibTransformLifecycleVerified;
        }
        if (setup.kind === "zlib-direct-flush-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.zlibDirectFlushLifecycleVerified =
            zlibDirectFlushLifecycleVerified;
        }
        if (
          setup.kind === "readline-interface-owner" ||
          setup.kind === "readline-interface-pause-owner"
        ) {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.inputLifecycleVerified =
            inputLifecycleVerified;
        }
        if (setup.kind === "net-terminal-owner") {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.netLifecycleVerified = netLifecycleVerified;
        }
        if (
          setup.kind === "timer-clear-root" ||
          setup.kind === "timer-factory-root" ||
          setup.kind === "timer-legacy-root" ||
          setup.kind === "timer-owner"
        ) {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.timerLifecycleVerified =
            timerLifecycleVerified;
        }
        if (
          setup.kind === "tls-server-construct-target" ||
          setup.kind === "tls-server-root-call"
        ) {
          capturedSuccess.cleanupPerformed = cleanupPerformed;
          capturedSuccess.tlsServerLifecycleVerified =
            tlsServerLifecycleVerified;
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
      if (setup.kind === "zlib-end-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibEndLifecycleVerified = zlibEndLifecycleVerified;
      }
      if (setup.kind === "zlib-process-chunk-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibProcessChunkOutputVerified =
          zlibProcessChunkOutputVerified;
      }
      if (setup.kind === "zlib-write-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibWriteLifecycleVerified =
          zlibWriteLifecycleVerified;
      }
      if (setup.kind === "zlib-flush-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibFlushLifecycleVerified =
          zlibFlushLifecycleVerified;
      }
      if (setup.kind === "zlib-params-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibParamsLifecycleVerified =
          zlibParamsLifecycleVerified;
      }
      if (setup.kind === "zlib-transform-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibTransformLifecycleVerified =
          zlibTransformLifecycleVerified;
      }
      if (setup.kind === "zlib-direct-flush-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.zlibDirectFlushLifecycleVerified =
          zlibDirectFlushLifecycleVerified;
      }
      if (isZlibSyncEncoderInvocation(config)) {
        success.zlibSyncEncoderOutputVerified =
          zlibSyncEncoderOutputVerified;
      }
      if (zlibSyncDecoderInput(config) !== null) {
        success.zlibSyncDecoderOutputVerified =
          zlibSyncDecoderOutputVerified;
      }
      if (zlibCallbackContract(config) !== null) {
        success.zlibCallbackOutputVerified =
          zlibCallbackOutputVerified;
      }
      if (
        setup.kind === "readline-interface-owner" ||
        setup.kind === "readline-interface-pause-owner"
      ) {
        success.cleanupPerformed = cleanupPerformed;
        success.inputLifecycleVerified = inputLifecycleVerified;
      }
      if (setup.kind === "net-terminal-owner") {
        success.cleanupPerformed = cleanupPerformed;
        success.netLifecycleVerified = netLifecycleVerified;
      }
      if (
        setup.kind === "timer-clear-root" ||
        setup.kind === "timer-factory-root" ||
        setup.kind === "timer-legacy-root" ||
        setup.kind === "timer-owner"
      ) {
        success.cleanupPerformed = cleanupPerformed;
        success.timerLifecycleVerified = timerLifecycleVerified;
      }
      if (
        setup.kind === "tls-server-construct-target" ||
        setup.kind === "tls-server-root-call"
      ) {
        success.cleanupPerformed = cleanupPerformed;
        success.tlsServerLifecycleVerified =
          tlsServerLifecycleVerified;
      }
      return failure("return", success);
    }

    if (zlibDirectFlushDispatchPromise) {
      return zlibDirectFlushDispatchPromise.then(function (outcome) {
        if (own.call(outcome, "result")) result = outcome.result;
        return zlibDirectFlushLifecyclePromise.then(function (verified) {
          if (!verified || own.call(outcome, "error")) {
            return failure("cleanup-mismatch", {
              setupKind: setup.kind,
              ownerExportName: setup.ownerExportName,
              sourceOperationAttempted: sourceOperationAttempted,
              prefillCallbackCalls:
                zlibDirectFlushLifecycleState.prefillCallbackCalls,
              prefillCallbackError:
                zlibDirectFlushLifecycleState.prefillCallbackError === null
                  ? null
                  : String(
                      zlibDirectFlushLifecycleState.prefillCallbackError,
                    ),
              callbackCalls:
                zlibDirectFlushLifecycleState.callbackCalls,
              callbackErrorCode:
                zlibDirectFlushLifecycleState.callbackError &&
                typeof zlibDirectFlushLifecycleState.callbackError.code ===
                  "string"
                  ? zlibDirectFlushLifecycleState.callbackError.code
                  : null,
              expectedCallbackErrorCode:
                setup.expectedCallbackErrorCode,
              streamError:
                zlibDirectFlushLifecycleState.streamError === null
                  ? null
                  : String(zlibDirectFlushLifecycleState.streamError),
              outputChunks:
                zlibDirectFlushLifecycleState.outputChunks,
              acceptedInputBeforeCleanup:
                zlibDirectFlushLifecycleState.acceptedInputBeforeCleanup,
              flushedBeforeCleanup:
                zlibDirectFlushLifecycleState.flushedBeforeCleanup,
              receiverNonTerminalBeforeCleanup:
                zlibDirectFlushLifecycleState
                  .receiverNonTerminalBeforeCleanup,
              cleanupPerformed: cleanupPerformed,
              receiverDestroyed:
                zlibDirectFlushLifecycleState.receiverDestroyed,
              nativeHandleClosed:
                zlibDirectFlushLifecycleState.nativeHandleClosed,
            });
          }
          return finishResult(result);
        });
      });
    }

    if (netLifecyclePromise) {
      return netLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
          });
        }
        return finishResult(result);
      });
    }

    if (tlsServerLifecyclePromise) {
      return tlsServerLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
          });
        }
        return finishResult(result);
      });
    }

    if (zlibCallbackPromise) {
      return zlibCallbackPromise.then(function (verified) {
        if (!verified) {
          return failure("callback-mismatch", {
            expectedContract: zlibCallbackContract(config).resultContract,
          });
        }
        zlibCallbackOutputVerified = true;
        return finishResult(result);
      });
    }

    if (zlibEndLifecyclePromise) {
      return zlibEndLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
          });
        }
        return finishResult(result);
      });
    }

    if (zlibWriteLifecyclePromise) {
      return zlibWriteLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
            callbackCalls: zlibWriteLifecycleState.callbackCalls,
            callbackError:
              zlibWriteLifecycleState.callbackError === null
                ? null
                : String(zlibWriteLifecycleState.callbackError),
            streamError:
              zlibWriteLifecycleState.streamError === null
                ? null
                : String(zlibWriteLifecycleState.streamError),
            outputLength: zlibWriteLifecycleState.outputLength,
            outputVerified: zlibWriteLifecycleState.outputVerified,
            finishEvents: zlibWriteLifecycleState.finishEvents,
            streamFlushed: zlibWriteLifecycleState.streamFlushed,
            writableEnded: zlibWriteLifecycleState.writableEnded,
            cleanupPerformed: cleanupPerformed,
            receiverDestroyed: zlibWriteLifecycleState.receiverDestroyed,
            nativeHandleClosed: zlibWriteLifecycleState.nativeHandleClosed,
          });
        }
        return finishResult(result);
      });
    }

    if (zlibFlushLifecyclePromise) {
      return zlibFlushLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
            callbackCalls: zlibFlushLifecycleState.callbackCalls,
            callbackError:
              zlibFlushLifecycleState.callbackError === null
                ? null
                : String(zlibFlushLifecycleState.callbackError),
            streamError:
              zlibFlushLifecycleState.streamError === null
                ? null
                : String(zlibFlushLifecycleState.streamError),
            outputChunks: zlibFlushLifecycleState.outputChunks,
            receiverNonTerminalBeforeCleanup:
              zlibFlushLifecycleState.receiverNonTerminalBeforeCleanup,
            cleanupPerformed: cleanupPerformed,
            receiverDestroyed: zlibFlushLifecycleState.receiverDestroyed,
            nativeHandleClosed: zlibFlushLifecycleState.nativeHandleClosed,
          });
        }
        return finishResult(result);
      });
    }

    if (zlibParamsLifecyclePromise) {
      return zlibParamsLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
            callbackCalls: zlibParamsLifecycleState.callbackCalls,
            callbackError:
              zlibParamsLifecycleState.callbackError === null
                ? null
                : String(zlibParamsLifecycleState.callbackError),
            streamError:
              zlibParamsLifecycleState.streamError === null
                ? null
                : String(zlibParamsLifecycleState.streamError),
            outputChunks: zlibParamsLifecycleState.outputChunks,
            selectedStateBeforeCleanup:
              zlibParamsLifecycleState.selectedStateBeforeCleanup,
            receiverNonTerminalBeforeCleanup:
              zlibParamsLifecycleState.receiverNonTerminalBeforeCleanup,
            cleanupPerformed: cleanupPerformed,
            receiverDestroyed: zlibParamsLifecycleState.receiverDestroyed,
            nativeHandleClosed:
              zlibParamsLifecycleState.nativeHandleClosed,
          });
        }
        return finishResult(result);
      });
    }

    if (zlibTransformLifecyclePromise) {
      return zlibTransformLifecyclePromise.then(function (verified) {
        if (!verified) {
          return failure("cleanup-mismatch", {
            setupKind: setup.kind,
            ownerExportName: setup.ownerExportName,
            callbackCalls: zlibTransformLifecycleState.callbackCalls,
            callbackError:
              zlibTransformLifecycleState.callbackError === null
                ? null
                : String(zlibTransformLifecycleState.callbackError),
            streamError:
              zlibTransformLifecycleState.streamError === null
                ? null
                : String(zlibTransformLifecycleState.streamError),
            outputChunks: zlibTransformLifecycleState.outputChunks,
            acceptedInputBeforeCleanup:
              zlibTransformLifecycleState.acceptedInputBeforeCleanup,
            receiverNonTerminalBeforeCleanup:
              zlibTransformLifecycleState.receiverNonTerminalBeforeCleanup,
            cleanupPerformed: cleanupPerformed,
            receiverDestroyed: zlibTransformLifecycleState.receiverDestroyed,
            nativeHandleClosed:
              zlibTransformLifecycleState.nativeHandleClosed,
          });
        }
        return finishResult(result);
      });
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
    if (
      setup &&
      (setup.kind === "zlib-write-owner" ||
        setup.kind === "zlib-flush-owner" ||
        setup.kind === "zlib-params-owner" ||
        setup.kind === "zlib-transform-owner" ||
        setup.kind === "zlib-direct-flush-owner") &&
      receiver
    ) {
      try {
        if (typeof receiver._closeNativeStream === "function") {
          receiver._closeNativeStream();
        }
        if (typeof receiver.destroy === "function") receiver.destroy();
        cleanupPerformed = receiver.destroyed === true;
      } catch (_zlibWriteCleanupError) {
        cleanupPerformed = false;
      }
    }
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
