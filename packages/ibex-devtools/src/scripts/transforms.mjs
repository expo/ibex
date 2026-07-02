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

// ===========================================================================
// Per-package compartment globals (LLP 0013 Mechanism 2)
// ===========================================================================
//
// @ref LLP 0013#mechanism-2 — rewrite free (unbound) references to endowed
// global names so they resolve against a per-package compartment scope object
// instead of the real global. This is the build-time / load-time half of the
// compartment design (the engine-native half is Phase 3). Three escape channels
// must be closed; this transform closes #1 (free identifiers) and #3 (direct
// eval). Channel #2 (sloppy-mode `this`) is closed by strict-mode emission at
// the wrapper level (see the loader), and the intrinsic evaluators are tamed by
// lockdown (Mechanism 1).
//
// Correctness hinges on lexical-scope analysis: a name that is bound in any
// enclosing scope (param, var/let/const, function/class name, catch param,
// import binding) is NOT free and must be left alone. Getting this wrong in
// either direction is a bug — rewriting a local breaks code; missing a free
// reference is a containment hole. We therefore track a precise scope chain with
// hoisting.

/**
 * The default set of powerful globals routed through the compartment scope.
 * Deliberately excludes `require`/`module`/`exports`/`__filename`/`__dirname`:
 * those are CommonJS wrapper parameters (local bindings), not free globals, and
 * routing them would break module loading. `require` attenuation is the import
 * graph's job (LLP 0013 Policy surface 3), not the free-global rewrite's.
 */
export const defaultCompartmentGlobals = Object.freeze([
  'process',
  'globalThis',
  'fetch',
  'Buffer',
  'eval',
  'Function',
  'XMLHttpRequest',
  'WebSocket',
  'importScripts',
  'queueMicrotask',
]);

/** Collect the binding names introduced by a binding target (destructuring). */
function collectPatternNames(node, out) {
  if (!node || typeof node !== 'object') return;
  switch (node.type) {
    case 'Identifier':
      out.add(node.name);
      return;
    case 'ObjectPattern':
      for (const prop of node.properties || []) {
        if (prop.type === 'RestElement') collectPatternNames(prop.argument, out);
        else collectPatternNames(prop.value, out);
      }
      return;
    case 'ArrayPattern':
      for (const el of node.elements || []) {
        if (el) collectPatternNames(el, out);
      }
      return;
    case 'AssignmentPattern':
      collectPatternNames(node.left, out);
      return;
    case 'RestElement':
      collectPatternNames(node.argument, out);
      return;
    default:
      return;
  }
}

/**
 * Collect `var` and function-declaration names hoisted to the enclosing
 * function scope. Recurses through statements and blocks but STOPS at nested
 * function boundaries (var hoisting does not cross them).
 */
function collectHoistedVars(node, out) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const child of node) collectHoistedVars(child, out);
    return;
  }
  switch (node.type) {
    case 'FunctionDeclaration':
      if (node.id) out.add(node.id.name);
      return; // do not descend into the function body
    case 'FunctionExpression':
    case 'ArrowFunctionExpression':
    case 'ClassDeclaration':
    case 'ClassExpression':
      return; // new function/class scope — hoisting stops
    case 'VariableDeclaration':
      if (node.kind === 'var') {
        for (const decl of node.declarations || []) {
          collectPatternNames(decl.id, out);
        }
      }
      return;
    default:
      break;
  }
  for (const key of Object.keys(node)) {
    if (key === 'start' || key === 'end' || key === 'type' || key === 'range') continue;
    const value = node[key];
    if (value && typeof value === 'object') collectHoistedVars(value, out);
  }
}

/** Collect block-lexical bindings (let/const/class/function) at one block level. */
function collectBlockLexical(statements, out) {
  for (const stmt of statements || []) {
    if (!stmt) continue;
    if (stmt.type === 'VariableDeclaration' && (stmt.kind === 'let' || stmt.kind === 'const')) {
      for (const decl of stmt.declarations || []) collectPatternNames(decl.id, out);
    } else if (stmt.type === 'ClassDeclaration' && stmt.id) {
      out.add(stmt.id.name);
    } else if (stmt.type === 'FunctionDeclaration' && stmt.id) {
      out.add(stmt.id.name);
    }
  }
}

/**
 * Rewrite free references to `globalNames` so they resolve against
 * `compartmentRef`. Pure: source string in, rewritten source string out.
 */
export function rewriteFreeGlobals(source, options = {}) {
  const {
    compartmentRef = '__compartment',
    globalNames = defaultCompartmentGlobals,
    rewriteEval = true,
  } = options;
  if (!source) return source;
  const names = globalNames instanceof Set ? globalNames : new Set(globalNames);
  if (names.size === 0 && !rewriteEval) return source;

  const ast = parseModuleOrScript(source);
  if (!ast) return source;

  const replacements = [];
  // Scope chain: array of Set<string>. Index 0 is the module/global scope.
  const scopes = [];

  const isBound = (name) => {
    for (let i = scopes.length - 1; i >= 0; i--) {
      if (scopes[i].has(name)) return true;
    }
    return false;
  };

  const pushScope = (names0) => {
    const s = new Set(names0);
    scopes.push(s);
    return s;
  };

  const rewriteIdentifier = (node, isCall) => {
    const name = node.name;
    // A binding in any enclosing scope means this is not a free global.
    if (isBound(name)) return;
    if (name === 'eval' && rewriteEval && isCall) {
      // Direct eval → compartment-bound evaluator (indirect-eval semantics).
      replacements.push({ start: node.start, end: node.end, text: `${compartmentRef}.eval` });
      return;
    }
    if (!names.has(name)) return;
    if (name === 'globalThis') {
      replacements.push({ start: node.start, end: node.end, text: compartmentRef });
    } else {
      replacements.push({ start: node.start, end: node.end, text: `${compartmentRef}.${name}` });
    }
  };

  // Walk with parent/key context so we can distinguish references from
  // non-references (property keys, binding positions, etc.).
  const walk = (node, parent, key, extraBindings) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const child of node) walk(child, parent, key, null);
      return;
    }
    if (!node.type) return;

    switch (node.type) {
      case 'Program': {
        const s = new Set();
        collectHoistedVars(node.body, s);
        collectBlockLexical(node.body, s);
        pushScope(s);
        for (const stmt of node.body) walk(stmt, node, 'body', null);
        scopes.pop();
        return;
      }
      case 'FunctionDeclaration':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression': {
        const s = new Set();
        // The function's own name is visible inside a named FunctionExpression.
        if (node.id && node.type === 'FunctionExpression') s.add(node.id.name);
        for (const param of node.params || []) collectPatternNames(param, s);
        // Body hoisting.
        const body = node.body;
        if (body && body.type === 'BlockStatement') {
          collectHoistedVars(body.body, s);
          collectBlockLexical(body.body, s);
        }
        // Default param values and computed member access on params are
        // evaluated in the new scope; walk params (skip pure identifier ids).
        pushScope(s);
        for (const param of node.params || []) walk(param, node, 'params', null);
        if (body && body.type === 'BlockStatement') {
          for (const stmt of body.body) walk(stmt, node, 'body', null);
        } else if (body) {
          walk(body, node, 'body', null); // arrow expression body
        }
        scopes.pop();
        return;
      }
      case 'ClassDeclaration':
      case 'ClassExpression': {
        const s = new Set();
        if (node.id) s.add(node.id.name);
        pushScope(s);
        if (node.superClass) walk(node.superClass, node, 'superClass', null);
        if (node.body) walk(node.body, node, 'body', null);
        scopes.pop();
        return;
      }
      case 'BlockStatement': {
        const s = new Set();
        collectBlockLexical(node.body, s);
        pushScope(s);
        for (const stmt of node.body) walk(stmt, node, 'body', null);
        scopes.pop();
        return;
      }
      case 'ForStatement':
      case 'ForInStatement':
      case 'ForOfStatement': {
        const s = new Set();
        if (node.type === 'ForStatement') {
          if (node.init && node.init.type === 'VariableDeclaration' && node.init.kind !== 'var') {
            for (const decl of node.init.declarations || []) collectPatternNames(decl.id, s);
          }
        } else if (node.left && node.left.type === 'VariableDeclaration' && node.left.kind !== 'var') {
          for (const decl of node.left.declarations || []) collectPatternNames(decl.id, s);
        }
        pushScope(s);
        if (node.type === 'ForStatement') {
          if (node.init) walk(node.init, node, 'init', null);
          if (node.test) walk(node.test, node, 'test', null);
          if (node.update) walk(node.update, node, 'update', null);
        } else {
          walk(node.left, node, 'left', null);
          walk(node.right, node, 'right', null);
        }
        walk(node.body, node, 'body', null);
        scopes.pop();
        return;
      }
      case 'CatchClause': {
        const s = new Set();
        if (node.param) collectPatternNames(node.param, s);
        pushScope(s);
        if (node.param) walk(node.param, node, 'param', null);
        walk(node.body, node, 'body', null);
        scopes.pop();
        return;
      }
      case 'Identifier': {
        // Reference position? Skip binding/property/label positions.
        if (parent) {
          if (parent.type === 'MemberExpression' && key === 'property' && !parent.computed) return;
          if (
            (parent.type === 'Property' || parent.type === 'MethodDefinition' || parent.type === 'PropertyDefinition') &&
            key === 'key' && !parent.computed
          ) return;
          if (parent.type === 'Property' && parent.shorthand) {
            // { process } — the value IS a reference; rewriting must expand to
            // { process: <ref>.process }. Handle at the Property node instead.
            return;
          }
          if (
            (parent.type === 'ImportSpecifier' || parent.type === 'ImportDefaultSpecifier' ||
              parent.type === 'ImportNamespaceSpecifier' || parent.type === 'ExportSpecifier')
          ) return;
          if ((parent.type === 'LabeledStatement' || parent.type === 'BreakStatement' ||
              parent.type === 'ContinueStatement') && key === 'label') return;
          if (parent.type === 'VariableDeclarator' && key === 'id') return;
          if ((parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression' ||
              parent.type === 'ArrowFunctionExpression' || parent.type === 'ClassDeclaration' ||
              parent.type === 'ClassExpression') && (key === 'id' || key === 'params')) return;
        }
        const isCall = parent && parent.type === 'CallExpression' && key === 'callee';
        rewriteIdentifier(node, isCall);
        return;
      }
      case 'Property': {
        if (node.shorthand && node.value && node.value.type === 'Identifier') {
          const name = node.value.name;
          if ((names.has(name) && !isBound(name)) ) {
            const text = name === 'globalThis' ? compartmentRef : `${compartmentRef}.${name}`;
            replacements.push({ start: node.start, end: node.end, text: `${name}: ${text}` });
          }
          return;
        }
        // Non-shorthand: walk key only if computed, then value.
        if (node.computed && node.key) walk(node.key, node, 'key', null);
        if (node.value) walk(node.value, node, 'value', null);
        return;
      }
      case 'MemberExpression': {
        walk(node.object, node, 'object', null);
        if (node.computed && node.property) walk(node.property, node, 'property', null);
        return;
      }
      case 'MetaProperty':
        return; // import.meta / new.target — not a free identifier
      default:
        break;
    }

    for (const k of Object.keys(node)) {
      if (k === 'start' || k === 'end' || k === 'type' || k === 'range') continue;
      const value = node[k];
      if (value && typeof value === 'object') walk(value, node, k, null);
    }
  };

  walk(ast, null, null, null);
  return applySourceReplacements(source, replacements);
}

/**
 * A Rolldown-style plugin that rewrites free globals per package. `resolvePackage`
 * maps a module id to its package selector (or null for first-party/root code,
 * which is left un-rewritten). `endowmentsFor` returns the global names routed
 * through the compartment for a given package.
 */
export function createCompartmentGlobalsPlugin({
  name = 'compartment-globals',
  registry = '__compartments',
  resolvePackage,
  endowmentsFor,
} = {}) {
  return {
    name,
    transform(code, id) {
      const pkg = resolvePackage ? resolvePackage(id) : packageOfModuleId(id);
      if (!pkg) return null; // first-party / root — trusted, not compartmentalized
      const globalNames = endowmentsFor ? endowmentsFor(pkg) : defaultCompartmentGlobals;
      // Each package resolves globals against its own compartment in the runtime
      // registry, so coexisting versions and distinct packages never share a
      // mutable compartment object. @ref LLP 0013#resolved-questions
      const compartmentRef = `${registry}[${JSON.stringify(pkg)}]`;
      const rewritten = rewriteFreeGlobals(code, { compartmentRef, globalNames });
      if (rewritten === code) return null;
      return { code: rewritten };
    },
  };
}

/**
 * Derive a package selector from a module id by locating the last
 * `node_modules/` segment. Returns null for ids with no node_modules ancestor
 * (first-party / workspace code → trusted root principal).
 *
 * @ref LLP 0013#resolved-questions — package name is the policy selector;
 * coexisting versions get separate compartments.
 */
export function packageOfModuleId(id) {
  if (typeof id !== 'string') return null;
  const marker = 'node_modules/';
  const idx = id.lastIndexOf(marker);
  if (idx === -1) return null;
  const rest = id.slice(idx + marker.length);
  const parts = rest.split('/');
  if (parts.length === 0) return null;
  if (parts[0].startsWith('@') && parts.length >= 2) {
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0];
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

export function createSharedBundlerPlugins({
  injectDirnameBindings = true,
  compartments = false,
} = {}) {
  const plugins = [];
  if (injectDirnameBindings) {
    plugins.push(createDirnameBindingsPlugin());
  }
  // @ref LLP 0013#mechanism-2 — the compartment rewrite runs in the per-module
  // transform hook (where the module id, hence package, is known) and must run
  // BEFORE the Hermes-compat lowering so lowering sees rewritten source.
  if (compartments) {
    plugins.push(
      createCompartmentGlobalsPlugin(
        typeof compartments === 'object' ? compartments : {},
      ),
    );
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
  compartments = false,
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
    plugins: createSharedBundlerPlugins({ injectDirnameBindings, compartments }),
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
