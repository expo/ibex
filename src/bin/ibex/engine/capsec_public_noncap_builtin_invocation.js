(function runNonCapabilityBuiltinInvocation(config) {
  var own = Object.prototype.hasOwnProperty;

  function valueType(value) {
    return value === null ? "null" : typeof value;
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
    var value = moduleValue;
    if (access.kind === "module-value") {
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
      value = holder[key];
    }
    return { value: value };
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
      return moduleValue.Buffer.from(argument.bytes);
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
      return failure("return", { valueType: valueType(target) });
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
    } else {
      return failure("unsupported-setup", { setupKind: setup.kind });
    }

    var callArguments = materializeList(
      config.arguments,
      moduleValue,
      bindings,
    );
    if (dispatchKind === "construct") {
      result = Reflect.construct(target, callArguments);
    } else {
      result = Reflect.apply(target, receiver, callArguments);
    }
    var actualResultType = valueType(result);
    if (actualResultType !== config.bodyEntryProof.resultType) {
      return failure("result-type-mismatch", {
        expectedResultType: config.bodyEntryProof.resultType,
        actualResultType: actualResultType,
        dispatchKind: dispatchKind,
      });
    }
    return failure("return", {
      valueType: actualResultType,
      dispatchKind: dispatchKind,
      bodyEntryProof: config.bodyEntryProof.kind,
    });
  } catch (error) {
    return failure("throw", {
      errorName: String((error && error.name) || "Error"),
      errorMessage: String((error && error.message) || error),
    });
  }
})
