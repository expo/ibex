/**
 * Shared source transforms for Hermes compatibility.
 *
 * - fixForOfScoping: converts for-of loops to .forEach() to work around
 *   Hermes closure-scoping bugs.
 * - transformAsyncGenerators: rewrites async generator functions into
 *   regular functions returning async iterables (Hermes lacks native support).
 */
import path from 'path';
import { parse } from 'acorn';
import {
  bundlerExternalModules,
  nodeBuiltins,
} from './builtin-manifest.mjs';

export const rolldownConditionNames = Object.freeze([
  'node',
  'import',
  'require',
  'default',
]);

export const hermesRolldownTarget = 'es2020';

export const runtimeImportMetaDefine = Object.freeze({
  'import.meta.filename': '__filename',
  'import.meta.dirname': '__dirname',
  'import.meta.main': 'true',
  'import.meta.url': '("file://" + __filename)',
  'import.meta.path': '__filename',
  'import.meta.file': '__filename && __filename.split("/").pop()',
  'import.meta.dir': '__dirname',
  'import.meta.require': 'require',
});

const compatExponentMarker = '__exactCompatPow__';

function parseModuleOrScript(source) {
  try {
    return parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      locations: false,
      ranges: true,
    });
  } catch {
    try {
      return parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        allowReturnOutsideFunction: true,
        locations: false,
        ranges: true,
      });
    } catch {
      return null;
    }
  }
}

export function fixForOfScoping(source) {
  if (!source || source.indexOf(' of ') === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  const replacements = [];

  const hasUnsafeControlFlow = (node, inFunction = false) => {
    if (!node || typeof node !== 'object') {
      return false;
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        if (hasUnsafeControlFlow(node[i], inFunction)) {
          return true;
        }
      }
      return false;
    }

    if (
      !inFunction &&
      (node.type === 'BreakStatement' ||
        node.type === 'ContinueStatement' ||
        node.type === 'ReturnStatement')
    ) {
      return true;
    }

    if (node.type === 'ForOfStatement' && node.await === true) {
      return true;
    }

    if (node.type === 'AwaitExpression' || node.type === 'YieldExpression') {
      return true;
    }

    if (
      node.type === 'FunctionDeclaration' ||
      node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression' ||
      node.type === 'ClassDeclaration' ||
      node.type === 'ClassExpression'
    ) {
      return false;
    }

    for (const key of Object.keys(node)) {
      if (key === 'start' || key === 'end' || key === 'type' || key === 'name') {
        continue;
      }
      const value = node[key];
      if (value && typeof value === 'object' && hasUnsafeControlFlow(value, inFunction)) {
        return true;
      }
    }

    return false;
  };

  const collectForOf = (node) => {
    if (!node || typeof node !== 'object') {
      return;
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        collectForOf(node[i]);
      }
      return;
    }

    if (node.type === 'ForOfStatement') {
      if (node.await === true) {
        collectForOf(node.left);
        collectForOf(node.right);
        collectForOf(node.body);
        return;
      }

      const right = node.right;
      const left = node.left;
      const body = node.body;

      if (
        !left ||
        !right ||
        !body ||
        right.start == null ||
        right.end == null ||
        body.start == null ||
        body.end == null
      ) {
        collectForOf(left);
        collectForOf(right);
        collectForOf(body);
        return;
      }

      let leftSource;
      let loopSetupSource = '';
      const iteratorSource = `__exactForOfIterator${replacements.length}`;
      const stepSource = `__exactForOfStep${replacements.length}`;
      if (left.type === 'VariableDeclaration') {
        const leftDecl = left.declarations?.[0];
        if (left.declarations?.length !== 1 || !leftDecl?.id) {
          collectForOf(left);
          collectForOf(right);
          collectForOf(body);
          return;
        }
        leftSource = source.slice(leftDecl.id.start, leftDecl.id.end);
        loopSetupSource = `${left.kind} ${leftSource} = ${stepSource}.value;\n`;
      } else {
        leftSource = source.slice(left.start, left.end);
        const assignmentSource =
          left.type === 'ObjectPattern' || left.type === 'ArrayPattern'
            ? `(${leftSource} = ${stepSource}.value);`
            : `${leftSource} = ${stepSource}.value;`;
        loopSetupSource = `${assignmentSource}\n`;
      }

      if (!leftSource) {
        collectForOf(left);
        collectForOf(right);
        collectForOf(body);
        return;
      }

      const rightSource = source.slice(right.start, right.end);
      const bodySource = source.slice(body.start, body.end);
      const blockInner =
        body.type === 'BlockStatement'
          ? source.slice(body.start + 1, body.end - 1)
          : bodySource;

      if (!rightSource || hasUnsafeControlFlow(body, false)) {
        collectForOf(left);
        collectForOf(right);
        collectForOf(body);
        return;
      }

      replacements.push({
        start: node.start,
        end: node.end,
        text: `{ const ${iteratorSource} = (${rightSource})[Symbol.iterator](); for (;;) { const ${stepSource} = ${iteratorSource}.next(); if (${stepSource}.done) break; ${loopSetupSource}${
          body.type === 'BlockStatement' ? blockInner : `${bodySource}`
        } } }`,
      });
      return;
    }

    for (const key of Object.keys(node)) {
      const value = node[key];
      if (!value) {
        continue;
      }
      if (key === 'start' || key === 'end' || key === 'type' || key === 'name') {
        continue;
      }
      if (typeof value === 'object') {
        collectForOf(value);
      }
    }
  };

  collectForOf(ast);

  if (!replacements.length) {
    return source;
  }

  replacements.sort((a, b) => b.start - a.start);
  let transformed = source;
  for (const replacement of replacements) {
    transformed =
      transformed.slice(0, replacement.start) +
      replacement.text +
      transformed.slice(replacement.end);
  }

  return transformed;
}

function isExponentiationExpression(node) {
  return node && node.type === 'BinaryExpression' && node.operator === '**';
}

function collectTopLevelExponentiation(source, ast, replacementBuilder, matcher) {
  const replacements = [];

  const walk = (node, parent = null) => {
    if (!node || typeof node !== 'object') {
      return;
    }
    if (Array.isArray(node)) {
      for (const child of node) {
        walk(child, parent);
      }
      return;
    }

    if (!node.type) {
      return;
    }

    if (matcher(node) && !(parent && matcher(parent))) {
      replacements.push({
        start: node.start,
        end: node.end,
        text: replacementBuilder(node),
      });
      return;
    }

    for (const key of Object.keys(node)) {
      if (key === 'start' || key === 'end' || key === 'type' || key === 'operator' || key === 'range') {
        continue;
      }
      const value = node[key];
      if (!value || typeof value !== 'object') {
        continue;
      }
      if (Array.isArray(value)) {
        for (const child of value) {
          walk(child, node);
        }
      } else {
        walk(value, node);
      }
    }
  };

  walk(ast);
  return replacements;
}

function applySourceReplacements(source, replacements) {
  if (!replacements.length) {
    return source;
  }

  replacements.sort((a, b) => b.start - a.start);
  let transformed = source;
  for (const replacement of replacements) {
    transformed =
      transformed.slice(0, replacement.start) +
      replacement.text +
      transformed.slice(replacement.end);
  }
  return transformed;
}

export function protectExponentiation(source) {
  if (!source || source.indexOf('**') === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  const render = (node) => {
    if (isExponentiationExpression(node)) {
      return `${compatExponentMarker}(${render(node.left)}, ${render(node.right)})`;
    }
    return source.slice(node.start, node.end);
  };

  const replacements = collectTopLevelExponentiation(
    source,
    ast,
    render,
    isExponentiationExpression,
  );

  return applySourceReplacements(source, replacements);
}

function isCompatExponentCall(node) {
  return (
    node &&
    node.type === 'CallExpression' &&
    node.callee &&
    node.callee.type === 'Identifier' &&
    node.callee.name === compatExponentMarker &&
    Array.isArray(node.arguments) &&
    node.arguments.length === 2
  );
}

export function restoreExponentiation(source) {
  if (!source || source.indexOf(compatExponentMarker) === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  const render = (node) => {
    if (isCompatExponentCall(node)) {
      return `((${render(node.arguments[0])}) ** (${render(node.arguments[1])}))`;
    }
    return source.slice(node.start, node.end);
  };

  const replacements = collectTopLevelExponentiation(
    source,
    ast,
    render,
    isCompatExponentCall,
  );

  return applySourceReplacements(source, replacements);
}

function renderBigIntConstructor(raw) {
  if (!raw || raw[raw.length - 1] !== 'n') {
    return null;
  }

  const literal = raw.slice(0, -1).replace(/_/g, '');
  if (!literal) {
    return null;
  }

  return `BigInt("${literal}")`;
}

export function transformBigIntLiterals(source) {
  if (!source || source.indexOf('n') === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  const replacements = [];
  const walk = (node) => {
    if (!node || typeof node !== 'object') {
      return;
    }

    if (Array.isArray(node)) {
      for (const child of node) {
        walk(child);
      }
      return;
    }

    if (
      node.type === 'Literal' &&
      Object.prototype.hasOwnProperty.call(node, 'bigint') &&
      node.start != null &&
      node.end != null
    ) {
      const replacement = renderBigIntConstructor(source.slice(node.start, node.end));
      if (replacement) {
        replacements.push({ start: node.start, end: node.end, text: replacement });
      }
      return;
    }

    for (const key of Object.keys(node)) {
      if (key === 'start' || key === 'end' || key === 'type' || key === 'name' || key === 'range') {
        continue;
      }
      const value = node[key];
      if (value && typeof value === 'object') {
        walk(value);
      }
    }
  };

  walk(ast);

  return applySourceReplacements(source, replacements);
}

/**
 * Transform async generator functions (async function*) into regular functions
 * returning async iterables. Hermes does not support async generators natively.
 */
export function transformAsyncGenerators(source) {
  if (!source || source.indexOf('async') === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  const replacements = [];

  const collectAsyncGens = (node, parent, parentKey) => {
    if (!node || typeof node !== 'object') {
      return;
    }
    if (Array.isArray(node)) {
      for (const child of node) {
        collectAsyncGens(child, parent, parentKey);
      }
      return;
    }

    if (
      (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') &&
      node.async &&
      node.generator &&
      node.body
    ) {
      const bodySource = source.slice(node.body.start + 1, node.body.end - 1);
      const params = node.params.map((param) => source.slice(param.start, param.end)).join(', ');
      const name = node.id ? node.id.name : '';

      const yieldReplacements = [];
      const collectYields = (current, depth) => {
        if (!current || typeof current !== 'object') {
          return;
        }
        if (Array.isArray(current)) {
          for (const child of current) {
            collectYields(child, depth);
          }
          return;
        }
        if (
          depth > 0 &&
          (current.type === 'FunctionDeclaration' ||
            current.type === 'FunctionExpression' ||
            current.type === 'ArrowFunctionExpression')
        ) {
          return;
        }
        if (current.type === 'YieldExpression') {
          const argSource = current.argument
            ? source.slice(current.argument.start, current.argument.end)
            : 'undefined';
          yieldReplacements.push({
            start: current.start - node.body.start - 1,
            end: current.end - node.body.start - 1,
            text: `await _yield(${argSource})`,
          });
          return;
        }
        for (const key of Object.keys(current)) {
          if (key === 'start' || key === 'end' || key === 'type') {
            continue;
          }
          const value = current[key];
          if (value && typeof value === 'object') {
            collectYields(value, depth);
          }
        }
      };
      collectYields(node.body, 0);

      yieldReplacements.sort((a, b) => b.start - a.start);
      let transformedBody = bodySource;
      for (const replacement of yieldReplacements) {
        transformedBody =
          transformedBody.slice(0, replacement.start) +
          replacement.text +
          transformedBody.slice(replacement.end);
      }

      const wrapperBody = `{
  var _items = [], _resolve = null, _done = false, _yieldReject = null, _error = null;
  var _ABORT = {};
  function _yield(v) {
    if (_done) return Promise.reject(_ABORT);
    return new Promise(function(resolve, reject) {
      var item = { value: v, done: false };
      _yieldReject = reject;
      if (_resolve) {
        var fn = _resolve;
        _resolve = null;
        fn(item);
        Promise.resolve().then(function() {
          _yieldReject = null;
          resolve();
        });
      }
      else {
        item._resume = function() {
          _yieldReject = null;
          resolve();
        };
        _items.push(item);
      }
    });
  }
  (async function() {${transformedBody}})().then(function() {
    _done = true;
    if (_resolve) { var fn = _resolve; _resolve = null; fn({ value: undefined, done: true }); }
  }, function(err) {
    _done = true;
    if (err === _ABORT) {
      _error = null;
      if (_resolve) { var fn = _resolve; _resolve = null; fn({ value: undefined, done: true }); }
      return;
    }
    _error = err;
    if (_resolve) { var fn = _resolve; _resolve = null; _error = null; fn(Promise.reject(err)); }
  });
  return {
    [Symbol.asyncIterator]: function() { return this; },
    next: function() {
      if (_items.length > 0) {
        var queued = _items.shift();
        if (queued && typeof queued._resume === 'function') {
          var resume = queued._resume;
          delete queued._resume;
          Promise.resolve().then(resume);
        }
        return Promise.resolve(queued);
      }
      if (_error) { var err = _error; _error = null; return Promise.reject(err); }
      if (_done) return Promise.resolve({ value: undefined, done: true });
      return new Promise(function(r) { _resolve = r; });
    },
    return: function() {
      _done = true;
      _error = null;
      _items.length = 0;
      if (_yieldReject) { var fn = _yieldReject; _yieldReject = null; fn(_ABORT); }
      if (_resolve) { var fn2 = _resolve; _resolve = null; fn2({ value: undefined, done: true }); }
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      _done = true;
      _error = null;
      _items.length = 0;
      if (_yieldReject) { var fn = _yieldReject; _yieldReject = null; fn(err); }
      if (_resolve) { var fn2 = _resolve; _resolve = null; fn2(Promise.reject(err)); }
      return Promise.reject(err);
    }
  };
}`;

      var replacementStart = node.start;
      var replacementEnd = node.end;
      var wrapper = `function ${name}(${params}) ${wrapperBody}`;
      if (
        parent &&
        parent.type === 'Property' &&
        parent.value === node &&
        parent.method &&
        parent.key
      ) {
        const keySource = source.slice(parent.key.start, parent.key.end);
        const propertyKey = parent.computed ? `[${keySource}]` : keySource;
        replacementStart = parent.start;
        replacementEnd = parent.end;
        wrapper = `${propertyKey}: function(${params}) ${wrapperBody}`;
      }

      replacements.push({ start: replacementStart, end: replacementEnd, text: wrapper });
      return;
    }

    for (const key of Object.keys(node)) {
      if (key === 'start' || key === 'end' || key === 'type' || key === 'name') {
        continue;
      }
      const value = node[key];
      if (value && typeof value === 'object') {
        collectAsyncGens(value, node, key);
      }
    }
  };

  collectAsyncGens(ast, null, null);

  if (!replacements.length) {
    return source;
  }

  replacements.sort((a, b) => b.start - a.start);
  let transformed = source;
  for (const replacement of replacements) {
    transformed =
      transformed.slice(0, replacement.start) +
      replacement.text +
      transformed.slice(replacement.end);
  }
  return transformed;
}

/** Node.js built-in module names shared between bundle and builtins scripts. */
export { nodeBuiltins };

function shouldSkipDirnameReplacement(parentNode, parentKey) {
  if (!parentNode) {
    return false;
  }

  if (parentNode.type === 'VariableDeclarator' && parentKey === 'id') {
    return true;
  }

  if (
    (parentNode.type === 'FunctionDeclaration' ||
      parentNode.type === 'FunctionExpression' ||
      parentNode.type === 'ArrowFunctionExpression') &&
    (parentKey === 'id' || parentKey === 'params')
  ) {
    return true;
  }

  if (
    (parentNode.type === 'ClassDeclaration' || parentNode.type === 'ClassExpression') &&
    parentKey === 'id'
  ) {
    return true;
  }

  if (
    (parentNode.type === 'Property' ||
      parentNode.type === 'MethodDefinition' ||
      parentNode.type === 'PropertyDefinition') &&
    parentKey === 'key' &&
    !parentNode.computed
  ) {
    return true;
  }

  if (parentNode.type === 'MemberExpression' && parentKey === 'property' && !parentNode.computed) {
    return true;
  }

  if (
    (parentNode.type === 'ImportSpecifier' ||
      parentNode.type === 'ImportDefaultSpecifier' ||
      parentNode.type === 'ImportNamespaceSpecifier' ||
      parentNode.type === 'ExportSpecifier') &&
    (parentKey === 'local' || parentKey === 'imported' || parentKey === 'exported')
  ) {
    return true;
  }

  if (
    (parentNode.type === 'LabeledStatement' ||
      parentNode.type === 'BreakStatement' ||
      parentNode.type === 'ContinueStatement') &&
    parentKey === 'label'
  ) {
    return true;
  }

  if (
    parentNode.type === 'ArrayPattern' ||
    parentNode.type === 'ObjectPattern' ||
    parentNode.type === 'RestElement' ||
    parentNode.type === 'AssignmentPattern'
  ) {
    return true;
  }

  return false;
}

export function replaceModuleDirnameBindings(source, id) {
  if (!source || !id || !path.isAbsolute(id)) {
    return source;
  }

  if (!source.includes('__dirname') && !source.includes('__filename')) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  const moduleDir = JSON.stringify(path.dirname(id));
  const moduleFile = JSON.stringify(id);
  const replacements = [];

  const walk = (node, parentNode = null, parentKey = null) => {
    if (!node || typeof node !== 'object') {
      return;
    }

    if (Array.isArray(node)) {
      for (const child of node) {
        walk(child, parentNode, parentKey);
      }
      return;
    }

    if (!node.type) {
      return;
    }

    if (node.type === 'Identifier' && (node.name === '__dirname' || node.name === '__filename')) {
      if (!shouldSkipDirnameReplacement(parentNode, parentKey)) {
        const replacementText = node.name === '__dirname' ? moduleDir : moduleFile;
        if (
          parentNode &&
          parentNode.type === 'Property' &&
          parentNode.shorthand &&
          parentKey === 'value'
        ) {
          replacements.push({
            start: parentNode.start,
            end: parentNode.end,
            text: `${node.name}: ${replacementText}`,
          });
        } else {
          replacements.push({
            start: node.start,
            end: node.end,
            text: replacementText,
          });
        }
      }
    }

    for (const key of Object.keys(node)) {
      if (key === 'start' || key === 'end' || key === 'type' || key === 'name' || key === 'range') {
        continue;
      }
      const value = node[key];
      if (!value || typeof value !== 'object') {
        continue;
      }
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child === 'object' && child.type) {
            walk(child, node, key);
          }
        }
      } else if (value.type) {
        walk(value, node, key);
      }
    }
  };

  walk(ast);

  if (!replacements.length) {
    return source;
  }

  const dedupedReplacements = replacements
    .sort((a, b) => {
      if (b.start !== a.start) {
        return b.start - a.start;
      }
      return b.end - a.end;
    })
    .filter((replacement, index, sorted) => {
      const previous = sorted[index - 1];
      return !previous || previous.start !== replacement.start || previous.end !== replacement.end;
    });

  let transformed = source;
  for (const replacement of dedupedReplacements) {
    transformed =
      transformed.slice(0, replacement.start) +
      replacement.text +
      transformed.slice(replacement.end);
  }

  return transformed;
}

export function applyHermesTransforms(source) {
  // @ref LLP 0005#bytecode-precompilation-hermesc — Hermes accepts BigInt(...) but rejects BigInt literal source.
  return transformBigIntLiterals(transformAsyncGenerators(fixForOfScoping(source)));
}

export function createDirnameBindingsPlugin({ name = 'inject-dirname' } = {}) {
  return {
    name,
    transform(code, id) {
      const transformed = replaceModuleDirnameBindings(code, id);
      if (transformed === code) {
        return null;
      }
      return { code: transformed };
    },
  };
}

export function createHermesCompatPlugin({ name = 'hermes-transforms' } = {}) {
  return {
    name,
    transform(code) {
      const fixed = fixForOfScoping(code);
      if (fixed === code) {
        return null;
      }
      return { code: fixed };
    },
    renderChunk(code) {
      const transformed = applyHermesTransforms(code);
      if (transformed === code) {
        return null;
      }
      return { code: transformed };
    },
  };
}

export function createBundlerExternalPredicate({
  extraExternalModules = [],
  keepRelativeCjsExternal = false,
} = {}) {
  const externalModules = new Set([...bundlerExternalModules, ...extraExternalModules]);

  return (id) => {
    if (externalModules.has(id)) {
      return true;
    }

    if (
      keepRelativeCjsExternal &&
      (id.startsWith('./') || id.startsWith('../')) &&
      id.endsWith('.cjs')
    ) {
      return true;
    }

    return false;
  };
}

export function createSharedBundlerPlugins({ injectDirnameBindings = true } = {}) {
  const plugins = [];
  if (injectDirnameBindings) {
    plugins.push(createDirnameBindingsPlugin());
  }
  plugins.push(createHermesCompatPlugin());
  return plugins;
}

export function createRolldownConfig({
  input,
  define,
  treeshake,
  extraExternalModules = [],
  keepRelativeCjsExternal = false,
  injectDirnameBindings = true,
} = {}) {
  const config = {
    input,
    external: createBundlerExternalPredicate({
      extraExternalModules,
      keepRelativeCjsExternal,
    }),
    resolve: {
      conditionNames: [...rolldownConditionNames],
    },
    plugins: createSharedBundlerPlugins({ injectDirnameBindings }),
    transform: {
      target: hermesRolldownTarget,
      ...(define ? { define } : {}),
    },
  };

  if (treeshake !== undefined) {
    config.treeshake = treeshake;
  }

  return config;
}
