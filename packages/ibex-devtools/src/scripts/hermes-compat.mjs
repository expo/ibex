/**
 * Canonical Hermes-compat source transforms (LLP 0019).
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

// @ref LLP 0019#decision — this is the CANONICAL AST authority for the
// Hermes-compat for-of rewrite (tier 1 of the documented two-tier split).
// The former byte-identical copy in ./transforms.mjs is now a re-export
// (ENG-22987); the string-scanner mirror in
// src/engine/bootstrap/module-loader.js (tier 2) converged on this output
// shape in ENG-22990 and is held to it by the shared corpus running through
// the real binary (run-hermes-compat-loader.mjs). Behavior changes land HERE
// first, with corpus fixtures; the scanner follows as far as its
// no-parser-in-bootstrap constraints allow. The exact-devtools sibling is the
// remaining independent copy until exact consolidates onto this file via the
// vendored ibex pin (ENG-22567).
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
      const errorSource = `__exactForOfError${rewriteCounter}`;
      const returnSource = `__exactForOfReturn${rewriteCounter}`;
      const ignoreSource = `__exactForOfIgnore${rewriteCounter}`;
      rewriteCounter += 1;

      // ENG-23036: native `for...of` runs IteratorClose (the iterator's
      // `return` method) on any abrupt completion of the body, so a generator's
      // `finally` / a custom `return()` runs when the body throws. The plain
      // `for (;;) { ...next()... body }` shape had no such call, silently
      // skipping cleanup. break/continue/return/await/yield already bail to raw
      // (which closes natively), so the only abrupt completion that reaches a
      // rewrite is a throw from the body; wrap just the body execution (not the
      // next() call, which native for-of does not IteratorClose on) and, on
      // throw, close the iterator before re-throwing. Per spec IteratorClose on
      // a throw completion the original error wins, so a throwing return() is
      // swallowed.
      const closeOnThrow = `catch (${errorSource}) { const ${returnSource} = ${iteratorSource}.return; if (typeof ${returnSource} === 'function') { try { ${returnSource}.call(${iteratorSource}); } catch (${ignoreSource}) {} } throw ${errorSource}; }`;

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
        text = `{ const ${iteratorSource} = (${transformedRight})[Symbol.iterator](); const ${bodyFnSource} = (${valueSource}) => { ${left.kind} ${leftSource} = ${valueSource};\n${blockInner} }; for (;;) { const ${stepSource} = ${iteratorSource}.next(); if (${stepSource}.done) break; try { ${bodyFnSource}(${stepSource}.value); } ${closeOnThrow} } }`;
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
        text = `{ const ${iteratorSource} = (${transformedRight})[Symbol.iterator](); for (;;) { const ${stepSource} = ${iteratorSource}.next(); if (${stepSource}.done) break; try { ${loopSetupSource}${blockInner} } ${closeOnThrow} } }`;
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

export function applySourceReplacements(source, replacements) {
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
 *
 * Runs the single-AST-pass rewrite to a fixpoint: each pass rewrites every
 * async generator that is not nested inside another one (the outer rewrite
 * leaves nested `async function*` text verbatim, since their yields belong to
 * their own scope), so each pass strips one nesting level (ENG-23124).
 */
export function transformAsyncGenerators(source) {
  let current = source;
  for (let pass = 0; pass < 100; pass += 1) {
    const next = transformAsyncGeneratorsPass(current, { mustParse: pass > 0 });
    if (next === current) {
      return current;
    }
    current = next;
  }
  // 100 passes means 100 levels of nested async generators — not a real
  // program. Fail loud rather than shipping untransformed async generators
  // that Hermes rejects at load (LLP 0018).
  throw new Error('transformAsyncGenerators did not reach a fixpoint after 100 passes');
}

function transformAsyncGeneratorsPass(source, { mustParse = false } = {}) {
  if (!source || source.indexOf('async') === -1) {
    return source;
  }

  const ast = parseModuleOrScript(source);
  if (!ast) {
    if (mustParse) {
      // The input of every pass after the first is this transform's own
      // output; failing to re-parse it means the previous pass emitted
      // invalid code. Never return it silently (LLP 0018).
      throw new Error('transformAsyncGenerators emitted unparseable output');
    }
    return source;
  }

  const replacements = [];

  const collectAsyncGens = (node, parent) => {
    if (!node || typeof node !== 'object') {
      return;
    }
    if (Array.isArray(node)) {
      for (const child of node) {
        collectAsyncGens(child, parent);
      }
      return;
    }

    if (
      (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') &&
      node.async &&
      node.generator &&
      node.body
    ) {
      const params = node.params.map((param) => source.slice(param.start, param.end)).join(', ');
      const name = node.id ? node.id.name : '';

      // Rewrite the yields that belong to THIS generator into _yield/_delegate
      // calls, stopping at nested function boundaries (a yield inside a nested
      // function belongs to that function's own generator scope; rewriting it
      // corrupted nested sync generators into parse errors, ENG-23124).
      // Returns the transformed text for `root`'s source range and recurses
      // into yield operands so nested yields (`yield yield 1`) stay rewritten.
      // Nested `async function*` subtrees are emitted verbatim here and picked
      // up by the next fixpoint pass.
      let usesDelegate = false;
      const rewriteYieldsIn = (root) => {
        const yieldReplacements = [];
        const collectYields = (current) => {
          if (!current || typeof current !== 'object') {
            return;
          }
          if (Array.isArray(current)) {
            for (const child of current) {
              collectYields(child);
            }
            return;
          }
          if (
            current.type === 'FunctionDeclaration' ||
            current.type === 'FunctionExpression' ||
            current.type === 'ArrowFunctionExpression'
          ) {
            return;
          }
          if (current.type === 'YieldExpression') {
            const argSource = current.argument ? rewriteYieldsIn(current.argument) : 'undefined';
            let text;
            if (current.delegate) {
              // ENG-23124: `yield*` delegates — pump the operand's (async or
              // sync) iterator through _yield instead of yielding the iterator
              // object as a single value.
              usesDelegate = true;
              text = `await _delegate(${argSource})`;
            } else {
              text = `await _yield(${argSource})`;
            }
            yieldReplacements.push({ start: current.start, end: current.end, text });
            return;
          }
          for (const key of Object.keys(current)) {
            if (key === 'start' || key === 'end' || key === 'type') {
              continue;
            }
            const value = current[key];
            if (value && typeof value === 'object') {
              collectYields(value);
            }
          }
        };
        if (root.type === 'FunctionDeclaration' || root.type === 'FunctionExpression' || root.type === 'ArrowFunctionExpression') {
          // A function used as a yield operand is its own yield scope.
          return source.slice(root.start, root.end);
        }
        collectYields(root);
        let text = source.slice(root.start, root.end);
        yieldReplacements.sort((a, b) => b.start - a.start);
        for (const replacement of yieldReplacements) {
          text =
            text.slice(0, replacement.start - root.start) +
            replacement.text +
            text.slice(replacement.end - root.start);
        }
        return text;
      };
      const transformedBody = rewriteYieldsIn(node.body).slice(1, -1);

      // Native `yield*` semantics, approximated: thread resume values into the
      // inner iterator's next(), return the inner iterator's completion value,
      // and close the inner iterator (IteratorClose) when the outer generator
      // is resumed abruptly (return()/throw()) while delegating. Divergence
      // from native: an outer throw() is not forwarded to the inner iterator's
      // throw() (the inner generator cannot catch it); the inner iterator is
      // closed and the error propagates from the delegation site.
      const delegateHelper = `
  async function _delegate(_iterable) {
    var _iter = (Symbol.asyncIterator && _iterable[Symbol.asyncIterator])
      ? _iterable[Symbol.asyncIterator]()
      : _iterable[Symbol.iterator]();
    var _sent;
    for (;;) {
      var _step = await _iter.next(_sent);
      if (_step.done) return await _step.value;
      try {
        _sent = await _yield(_step.value);
      } catch (_resumeErr) {
        var _closeFn = _iter.return;
        if (typeof _closeFn === 'function') {
          try { await _closeFn.call(_iter); } catch (_closeErr) {}
        }
        throw _resumeErr;
      }
    }
  }`;

      // @ref LLP 0005#2-transformed-builtin-modules — Hermes lacks native
      // async generators, so we desugar to a demand-driven async iterator that
      // must reproduce ES async-generator semantics (ENG-23036, ENG-23124):
      //   - lazy start: the body runs on the first next()/return()/throw(), not
      //     at generator-call time (no premature side effects / resource acq);
      //   - value threading: `x = yield e` resolves to the argument of the
      //     next() that resumes it (`req.sent`), not undefined;
      //   - concurrency: consumers queue FIFO in `_requests` with a completion
      //     kind per request ('next' | 'return' | 'throw'), so overlapping
      //     calls never orphan a promise or reorder results — the body is
      //     sequential (one suspended `_yield` at a time) with backpressure;
      //   - operand await: AsyncGeneratorYield awaits the yield operand, so
      //     consumers receive settled values and an operand rejection throws at
      //     the yield site inside the body;
      //   - resume completions: return()/throw() while suspended resume the
      //     body (throw() via a catchable rejection, so `try { yield } catch`
      //     recovery yields keep the generator alive; return() via the _ABORT
      //     sentinel carrying the return value) and settle from the body's
      //     ACTUAL settlement, so `finally` blocks — including async ones, and
      //     yields inside finally — complete before the caller's promise
      //     resolves. Documented divergence (corpus-pinned, ENG-23124): a bare
      //     `catch` around a yield observes the _ABORT sentinel on return(),
      //     where native return-completion semantics skip catch blocks; that
      //     would require a state-machine rewrite of the body;
      //   - this/arguments/super: the body runs in an arrow chain (`_start`
      //     and the body IIFE are arrows), so `this`, `arguments`, `super`,
      //     and `new.target` resolve to the wrapper function — the original
      //     call's receiver and arguments — not to the driver plumbing.
      const wrapperBody = `{
  var _requests = [];
  var _active = null;
  var _resume = null, _resumeReject = null;
  var _started = false, _done = false;
  var _ABORT = { returned: undefined };
  function _doneResult(v) {
    return Promise.resolve(v).then(function(_v) { return { value: _v, done: true }; });
  }
  function _pump() {
    if (_resume && _requests.length > 0) {
      var req = _requests.shift();
      _active = req;
      var r = _resume, rj = _resumeReject;
      _resume = null;
      _resumeReject = null;
      if (req.kind === 'throw') { rj(req.sent); }
      else if (req.kind === 'return') { _ABORT.returned = req.sent; rj(_ABORT); }
      else { r(req.sent); }
    }
  }
  function _flushDone() {
    while (_requests.length > 0) {
      var req = _requests.shift();
      if (req.kind === 'throw') { req.reject(req.sent); }
      else if (req.kind === 'return') { req.resolve(_doneResult(req.sent)); }
      else { req.resolve({ value: undefined, done: true }); }
    }
  }
  function _yield(v) {
    return Promise.resolve(v).then(function(_settled) {
      if (_done) return Promise.reject(_ABORT);
      if (_active) { var a = _active; _active = null; a.resolve({ value: _settled, done: false }); }
      return new Promise(function(resolve, reject) {
        _resume = resolve;
        _resumeReject = reject;
        _pump();
      });
    });
  }${usesDelegate ? delegateHelper : ''}
  var _start = (_firstReq) => {
    _started = true;
    _active = _firstReq;
    (async () => {${transformedBody}})().then(function(_ret) {
      _done = true;
      if (_active) { var a = _active; _active = null; a.resolve({ value: _ret, done: true }); }
      _flushDone();
    }, function(_err) {
      _done = true;
      if (_err === _ABORT) {
        if (_active) { var a = _active; _active = null; a.resolve(_doneResult(_ABORT.returned)); }
        _flushDone();
        return;
      }
      if (_active) { var a = _active; _active = null; a.reject(_err); }
      _flushDone();
    });
  };
  function _enqueue(kind, sent) {
    return new Promise(function(resolve, reject) {
      var req = { kind: kind, sent: sent, resolve: resolve, reject: reject };
      if (_done) {
        if (kind === 'throw') { reject(sent); }
        else if (kind === 'return') { resolve(_doneResult(sent)); }
        else { resolve({ value: undefined, done: true }); }
        return;
      }
      if (!_started) {
        if (kind === 'return') { _done = true; resolve(_doneResult(sent)); return; }
        if (kind === 'throw') { _done = true; reject(sent); return; }
        _start(req);
        return;
      }
      _requests.push(req);
      _pump();
    });
  }
  return {
    [Symbol.asyncIterator]: function() { return this; },
    next: function(_sent) { return _enqueue('next', _sent); },
    return: function(_value) { return _enqueue('return', _value); },
    throw: function(_err) { return _enqueue('throw', _err); }
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
      } else if (
        parent &&
        parent.type === 'MethodDefinition' &&
        parent.value === node &&
        parent.key
      ) {
        // ENG-23124: class methods — replace the whole MethodDefinition
        // (which includes `async *` and the key), not just the function
        // expression span, and preserve `static` and computed keys. The old
        // default branch emitted `class C { async *m function () {…} }`.
        const keySource = source.slice(parent.key.start, parent.key.end);
        const propertyKey = parent.computed ? `[${keySource}]` : keySource;
        replacementStart = parent.start;
        replacementEnd = parent.end;
        wrapper = `${parent.static ? 'static ' : ''}${propertyKey}(${params}) ${wrapperBody}`;
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
        collectAsyncGens(value, node);
      }
    }
  };

  collectAsyncGens(ast, null);

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
