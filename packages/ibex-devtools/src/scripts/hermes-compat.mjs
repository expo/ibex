/**
 * Canonical Hermes-compat source transforms (LLP 0312).
 *
 * This module is the single source of truth for the Hermes-compat bundle-time
 * transforms shared across Ibex build tooling and, via the vendored submodule,
 * Exact devtools (ENG-22987 / ENG-22988). It is intentionally dependency-light:
 * it depends only on the local Oxc parse helper, not on package-manifest
 * generation, import-grants, bundler assembly, or other devtools side effects.
 *
 * - fixForOfScoping: rewrites for-of loops (including loops nested inside
 *   rewritten bodies, ENG-22559) into explicit iterator-protocol loops whose
 *   `let`/`const` loop variable is bound inside a per-iteration-invoked
 *   function (ENG-22569) so closures created in the body capture a fresh
 *   binding per iteration on shipping Hermes (ES6BlockScoping=false).
 * - protectExponentiation / restoreExponentiation: park `**` behind a marker
 *   call across a downlevel pass that cannot emit it, then restore it.
 * - transformBigIntLiterals: rewrite BigInt literals to `BigInt(...)` calls
 *   (Hermes accepts the constructor but rejects literal BigInt source).
 * - transformAsyncGenerators: rewrites async generator functions into regular
 *   functions returning async iterables (Hermes lacks native support).
 * - applyHermesTransforms: the canonical composition of the above.
 */
import { parseModuleOrScript } from './parse-js.mjs';

const compatExponentMarker = '__exactCompatPow__';

// DUPLICATION SEAM (ENG-22559 / ENG-22558): this AST-based fixForOfScoping
// has two independent siblings solving the same Hermes function-scoped-const
// closure pitfall — the string-scanner twin in
// vendor/ibex/src/engine/bootstrap/module-loader.js (nested-loop fix in ibex
// 6c83354, ENG-22558) and a byte-identical AST copy in
// vendor/ibex/packages/ibex-devtools/src/scripts/transforms.mjs. The
// implementations have demonstrably drifted before; keep behavior fixes in
// sync across all three until they are consolidated.
export function fixForOfScoping(source) {
  if (!source || source.indexOf(' of ') === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    return source;
  }

  // Counter for the generated __exactForOfIterator/__exactForOfStep/
  // __exactForOfValue/__exactForOfBody names. Incremented only when a loop is
  // actually rewritten, at the same pre-order walk position the old
  // `replacements.length` numbering used (ENG-22559), so temporaries never
  // collide across sibling or nested rewrites.
  let rewriteCounter = 0;

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

  // The ENG-22569 output shape moves the loop body into an arrow function
  // invoked once per iteration, so `var` declarations and function
  // declarations in the body (outside nested function/class boundaries) would
  // change scope: a `var` would no longer hoist to the enclosing function,
  // and a sloppy-mode function declaration would lose its Annex B
  // function-scope binding. Loops whose bodies contain either are left raw —
  // raw for-of runs correctly on Hermes apart from the capture-last closure
  // pitfall, which is strictly less wrong than the old iterator-protocol
  // shape's capture-undefined behavior.
  const hasHoistingHazard = (node) => {
    if (!node || typeof node !== 'object') {
      return false;
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        if (hasHoistingHazard(node[i])) {
          return true;
        }
      }
      return false;
    }

    if (node.type === 'FunctionDeclaration') {
      return true;
    }

    if (node.type === 'VariableDeclaration' && node.kind === 'var') {
      return true;
    }

    if (
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
      if (value && typeof value === 'object' && hasHoistingHazard(value)) {
        return true;
      }
    }

    return false;
  };

  const collectPatternNames = (pattern, names) => {
    if (!pattern || typeof pattern !== 'object') {
      return;
    }
    switch (pattern.type) {
      case 'Identifier':
        names.add(pattern.name);
        return;
      case 'ObjectPattern':
        for (const property of pattern.properties || []) {
          collectPatternNames(property, names);
        }
        return;
      case 'Property':
        collectPatternNames(pattern.value, names);
        return;
      case 'ArrayPattern':
        for (const element of pattern.elements || []) {
          collectPatternNames(element, names);
        }
        return;
      case 'AssignmentPattern':
        collectPatternNames(pattern.left, names);
        return;
      case 'RestElement':
        collectPatternNames(pattern.argument, names);
        return;
      default:
        return;
    }
  };

  // The loop variable declaration and the body statements share one block in
  // the generated wrapper, so a body-top-level lexical redeclaration of a
  // bound name would be a SyntaxError in the output (the old shape had the
  // same latent hazard; now it bails instead of generating broken code).
  const bodyRedeclaresBoundNames = (body, boundNames) => {
    if (!boundNames.size || body.type !== 'BlockStatement' || !Array.isArray(body.body)) {
      return false;
    }
    for (const statement of body.body) {
      if (statement.type === 'VariableDeclaration') {
        for (const declaration of statement.declarations || []) {
          const declared = new Set();
          collectPatternNames(declaration.id, declared);
          for (const declaredName of declared) {
            if (boundNames.has(declaredName)) {
              return true;
            }
          }
        }
      } else if (
        (statement.type === 'FunctionDeclaration' || statement.type === 'ClassDeclaration') &&
        statement.id &&
        boundNames.has(statement.id.name)
      ) {
        return true;
      }
    }
    return false;
  };

  // Returns the transformed source text for `node`'s range: collects
  // rewritable for-of loops inside the subtree into a fresh list and splices
  // them into the original slice. Used to rewrite the body (and right) of a
  // loop that is itself about to be rewritten (ENG-22559): the old code
  // emitted the raw body slice, so a nested `for (const y of ys) { ... }`
  // inside a rewritten outer loop survived untransformed and the Hermes
  // function-scoped-const closure pitfall persisted one level down. This is
  // the AST-walker equivalent of the ibex string scanner's pre-wrap
  // rewriteForOfChunk recursion (ibex 6c83354, ENG-22558). Recursion runs on
  // the ORIGINAL body text before wrapping, so generated code is never
  // re-scanned, and bail decisions (which already inspected the full subtree)
  // are unchanged — inner rewrites are only added where the outer already
  // rewrote.
  const transformSlice = (node) => {
    const innerReplacements = [];
    collectForOf(node, innerReplacements);
    let text = source.slice(node.start, node.end);
    if (!innerReplacements.length) {
      return text;
    }
    innerReplacements.sort((a, b) => b.start - a.start);
    for (const replacement of innerReplacements) {
      text =
        text.slice(0, replacement.start - node.start) +
        replacement.text +
        text.slice(replacement.end - node.start);
    }
    return text;
  };

  const collectForOf = (node, replacements) => {
    if (!node || typeof node !== 'object') {
      return;
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        collectForOf(node[i], replacements);
      }
      return;
    }

    if (node.type === 'ForOfStatement') {
      if (node.await === true) {
        collectForOf(node.left, replacements);
        collectForOf(node.right, replacements);
        collectForOf(node.body, replacements);
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
        collectForOf(left, replacements);
        collectForOf(right, replacements);
        collectForOf(body, replacements);
        return;
      }

      // All bail checks run before a rewrite is committed (and before a
      // temporary-name index is consumed): the pre-ENG-22559 conditions plus
      // the ENG-22569 wrapper hazards (var/function-declaration hoisting and
      // bound-name redeclaration) for loops that need per-iteration bindings.
      let leftDecl = null;
      if (left.type === 'VariableDeclaration') {
        leftDecl = left.declarations?.[0];
        if (left.declarations?.length !== 1 || !leftDecl?.id) {
          collectForOf(left, replacements);
          collectForOf(right, replacements);
          collectForOf(body, replacements);
          return;
        }
      }

      const leftSource = leftDecl
        ? source.slice(leftDecl.id.start, leftDecl.id.end)
        : source.slice(left.start, left.end);

      if (!leftSource) {
        collectForOf(left, replacements);
        collectForOf(right, replacements);
        collectForOf(body, replacements);
        return;
      }

      const rightSource = source.slice(right.start, right.end);

      if (!rightSource || hasUnsafeControlFlow(body, false)) {
        collectForOf(left, replacements);
        collectForOf(right, replacements);
        collectForOf(body, replacements);
        return;
      }

      // Only `let`/`const` loop variables need (and per the spec get) a fresh
      // binding per iteration; `for (var x of ...)` and `for (x of ...)`
      // assign one function-scoped/outer binding, which the plain
      // iterator-protocol shape already models correctly on every engine.
      const needsPerIterationBinding =
        leftDecl != null && (left.kind === 'let' || left.kind === 'const');

      if (needsPerIterationBinding) {
        const boundNames = new Set();
        collectPatternNames(leftDecl.id, boundNames);
        if (hasHoistingHazard(body) || bodyRedeclaresBoundNames(body, boundNames)) {
          collectForOf(left, replacements);
          collectForOf(right, replacements);
          collectForOf(body, replacements);
          return;
        }
      }

      const iteratorSource = `__exactForOfIterator${rewriteCounter}`;
      const stepSource = `__exactForOfStep${rewriteCounter}`;
      const valueSource = `__exactForOfValue${rewriteCounter}`;
      const bodyFnSource = `__exactForOfBody${rewriteCounter}`;
      rewriteCounter += 1;

      // Recursively transform the right expression and the body BEFORE
      // wrapping (ENG-22559): nested for-of loops — directly in the body, or
      // inside function expressions in the body or the iterated expression —
      // get their own rewrites instead of being emitted raw.
      const transformedRight = transformSlice(right);
      const transformedBody = transformSlice(body);
      const blockInner =
        body.type === 'BlockStatement'
          ? transformedBody.slice(1, -1)
          : transformedBody;

      let text;
      if (needsPerIterationBinding) {
        // ENG-22569 shape: the body lives in an arrow function (hoisted out
        // of the loop so it is allocated once) that is invoked with the
        // current iteration's value. Function parameters get a fresh binding
        // per call on every Hermes configuration — this is the property that
        // makes the ibex loader's forEach twin correct — while the arrow
        // preserves `this`, `arguments`, `super`, and `new.target`, and the
        // explicit iterator protocol keeps live/lazy iteration semantics
        // (`Array.from` would snapshot the iterable).
        text = `{ const ${iteratorSource} = (${transformedRight})[Symbol.iterator](); const ${bodyFnSource} = (${valueSource}) => { ${left.kind} ${leftSource} = ${valueSource};\n${blockInner} }; for (;;) { const ${stepSource} = ${iteratorSource}.next(); if (${stepSource}.done) break; ${bodyFnSource}(${stepSource}.value); } }`;
      } else {
        let loopSetupSource;
        if (leftDecl) {
          loopSetupSource = `${left.kind} ${leftSource} = ${stepSource}.value;\n`;
        } else {
          const assignmentSource =
            left.type === 'ObjectPattern' || left.type === 'ArrayPattern'
              ? `(${leftSource} = ${stepSource}.value);`
              : `${leftSource} = ${stepSource}.value;`;
          loopSetupSource = `${assignmentSource}\n`;
        }
        text = `{ const ${iteratorSource} = (${transformedRight})[Symbol.iterator](); for (;;) { const ${stepSource} = ${iteratorSource}.next(); if (${stepSource}.done) break; ${loopSetupSource}${blockInner} } }`;
      }

      replacements.push({
        start: node.start,
        end: node.end,
        text,
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
        collectForOf(value, replacements);
      }
    }
  };

  const replacements = [];
  collectForOf(ast, replacements);

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

export function applyHermesTransforms(source) {
  // @ref LLP 0005#bytecode-precompilation-hermesc — Hermes accepts BigInt(...) but rejects BigInt literal source.
  return transformBigIntLiterals(transformAsyncGenerators(fixForOfScoping(source)));
}

