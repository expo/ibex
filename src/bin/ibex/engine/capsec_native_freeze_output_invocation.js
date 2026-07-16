(function executeNativeFreezeOutputInvocation(config) {
  'use strict';

  var attempted = false;
  var identityProven = false;
  var freezingSemanticsProven = false;

  function exactKeys(value, expected, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError(label + ' must be an object');
    }
    var actual = Object.keys(value).sort().join('\n');
    var wanted = expected.slice().sort().join('\n');
    if (actual !== wanted) {
      throw new TypeError(label + ' has unexpected fields');
    }
  }

  function thrown(error) {
    return {
      kind: 'throw',
      sourceOperationAttempted: attempted,
      identityProven: identityProven,
      freezingSemanticsProven: freezingSemanticsProven,
      rawOutput: {
        kind: 'throw',
        rawValueShape: 'throw',
        value: null,
        errorCode: 'ERR_IBEX_NATIVE_FREEZE_IDENTITY_PROBE',
        errorName: String(error && error.name || 'Error')
      }
    };
  }

  try {
    exactKeys(config, [
      'invocationSchema',
      'kind',
      'coverageEdgeId',
      'coverageClassification',
      'surfaceObservedKey',
      'sourceDescriptor',
      'sourceDescriptorDigest',
      'operation',
      'completion'
    ], 'native freeze invocation');
    exactKeys(config.sourceDescriptor, [
      'kind',
      'globalName',
      'implementationSymbol',
      'implementationPath',
      'freezeSemantics',
      'inventorySourceRefs',
      'implementationSourceRefs'
    ], 'native freeze source descriptor');
    exactKeys(config.operation, [
      'kind',
      'sentinelId',
      'identityCheck',
      'freezeCheck'
    ], 'native freeze operation');
    exactKeys(config.completion, ['kind'], 'native freeze completion');

    var descriptor = config.sourceDescriptor;
    var operation = config.operation;
    if (config.invocationSchema !== 'ibex/capsec-native-freeze-output-invocation/1' ||
        config.kind !== 'native-freeze-output' ||
        config.coverageClassification !== 'non-capability' ||
        config.surfaceObservedKey !== 'native-op:' + descriptor.globalName ||
        descriptor.kind !== 'native-freeze-global' ||
        (descriptor.globalName !== '__exactDeepFreeze' &&
         descriptor.globalName !== '__exactNativeFreeze') ||
        operation.kind !== 'native-freeze-argument-identity' ||
        operation.identityCheck !== 'strict-equality' ||
        config.completion.kind !== 'synchronous-loaded-hermes') {
      throw new TypeError('native freeze invocation is not source-bound');
    }

    var freeze = globalThis[descriptor.globalName];
    if (typeof freeze !== 'function') {
      throw new TypeError(descriptor.globalName + ' is unavailable');
    }

    var argument;
    var child = null;
    if (operation.sentinelId === 'primitive-number-1729') {
      if (operation.freezeCheck !== 'not-applicable') {
        throw new TypeError('primitive freeze check must be inapplicable');
      }
      argument = 1729;
    } else if (operation.sentinelId === 'null-prototype-two-node-graph-v1') {
      child = Object.create(null);
      child.leaf = 'ibex-freeze-child';
      argument = Object.create(null);
      argument.child = child;
      if (operation.freezeCheck !== descriptor.freezeSemantics) {
        throw new TypeError('object freeze check drifted from its source');
      }
    } else {
      throw new TypeError('unsupported native freeze sentinel');
    }

    attempted = true;
    var returned = Reflect.apply(freeze, globalThis, [argument]);
    if (returned !== argument) {
      throw new TypeError('native freeze did not return argument zero');
    }
    identityProven = true;

    if (child === null) {
      freezingSemanticsProven = true;
    } else {
      if (!Object.isFrozen(argument)) {
        throw new TypeError('native freeze left the root mutable');
      }
      if (operation.freezeCheck === 'deep' && !Object.isFrozen(child)) {
        throw new TypeError('deep freeze left the child mutable');
      }
      if (operation.freezeCheck === 'shallow' && Object.isFrozen(child)) {
        throw new TypeError('shallow freeze unexpectedly froze the child');
      }
      freezingSemanticsProven = true;
    }

    return {
      kind: 'return',
      sourceOperationAttempted: true,
      identityProven: true,
      freezingSemanticsProven: true,
      rawOutput: {
        kind: 'return',
        rawValueShape: 'argument-identity',
        value: 'same-as-argument-0',
        errorCode: null
      }
    };
  } catch (error) {
    return thrown(error);
  }
})
