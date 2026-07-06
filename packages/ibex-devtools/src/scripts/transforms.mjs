/**
 * Shared source transforms for Hermes compatibility.
 *
 * - fixForOfScoping: rewrites for-of loops (including loops nested inside
 *   rewritten bodies, ENG-22559) into explicit iterator-protocol loops whose
 *   `let`/`const` loop variable is bound inside a per-iteration-invoked
 *   function (ENG-22569) so closures created in the body capture a fresh
 *   binding per iteration on shipping Hermes (ES6BlockScoping=false).
 * - transformAsyncGenerators: rewrites async generator functions into
 *   regular functions returning async iterables (Hermes lacks native support).
 */
import fs from 'fs';
import path from 'path';
import {
  bundlerExternalModules,
  nodeBuiltins,
} from './builtin-manifest.mjs';
import { createImportGrantsPlugin } from './import-grants.mjs';
import { parseModuleOrScript } from './parse-js.mjs';

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

// Canonical Hermes-compat transforms now live in ./hermes-compat.mjs (LLP 0019,
// ENG-22987). They are imported here for internal use (createHermesCompatPlugin)
// and re-exported so existing consumers of @ibex/devtools/scripts/transforms keep
// working unchanged.
import {
  fixForOfScoping,
  protectExponentiation,
  restoreExponentiation,
  transformBigIntLiterals,
  transformAsyncGenerators,
  applyHermesTransforms,
  applySourceReplacements,
} from './hermes-compat.mjs';

export {
  fixForOfScoping,
  protectExponentiation,
  restoreExponentiation,
  transformBigIntLiterals,
  transformAsyncGenerators,
  applyHermesTransforms,
  applySourceReplacements,
};

/** Node.js built-in module names shared between bundle and builtins scripts. */
export { nodeBuiltins };

function shouldSkipDirnameReplacement(parentNode, parentKey, grandParentNode) {
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

  // Assignment targets (ENG-23137): rewriting the LHS of `__dirname = ...`,
  // the operand of `__dirname++`, or a for-in/of assignment target would emit
  // an invalid assignment to a string literal.
  if (
    (parentNode.type === 'AssignmentExpression' ||
      parentNode.type === 'ForInStatement' ||
      parentNode.type === 'ForOfStatement') &&
    parentKey === 'left'
  ) {
    return true;
  }
  if (parentNode.type === 'UpdateExpression' && parentKey === 'argument') {
    return true;
  }

  // Destructuring/binding patterns: skip only TRUE binding positions — the
  // element/target being bound. A default value (`AssignmentPattern.right`,
  // e.g. `function f(dir = __dirname)`) is an ordinary expression and must be
  // inlined; the old blanket pattern-parent skip left it to fall back to the
  // bundled chunk's `__dirname`, a silently wrong path for modules in
  // subdirectories (ENG-23137).
  if (parentNode.type === 'ArrayPattern' && parentKey === 'elements') {
    return true;
  }
  if (parentNode.type === 'RestElement' && parentKey === 'argument') {
    return true;
  }
  if (parentNode.type === 'AssignmentPattern' && parentKey === 'left') {
    return true;
  }
  // `const { __dirname } = o` / `const { x: __dirname } = o`: the identifier
  // sits at Property.value inside an ObjectPattern — a binding, not a value
  // (rewriting it emitted an invalid destructuring target).
  if (
    parentNode.type === 'Property' &&
    parentKey === 'value' &&
    grandParentNode &&
    grandParentNode.type === 'ObjectPattern'
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

  const walk = (node, parentNode = null, parentKey = null, grandParentNode = null) => {
    if (!node || typeof node !== 'object') {
      return;
    }

    if (Array.isArray(node)) {
      for (const child of node) {
        walk(child, parentNode, parentKey, grandParentNode);
      }
      return;
    }

    if (!node.type) {
      return;
    }

    if (node.type === 'Identifier' && (node.name === '__dirname' || node.name === '__filename')) {
      if (!shouldSkipDirnameReplacement(parentNode, parentKey, grandParentNode)) {
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
            walk(child, node, key, parentNode);
          }
        }
      } else if (value.type) {
        walk(value, node, key, parentNode);
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
  // `global`/`self` alias the real global; if not routed through the compartment
  // they are a one-hop leak to every withheld capability. (ENG-22625)
  'global',
  'self',
  // `Ibex` exposes the dynamic-permission surface (broker/request); withhold it
  // from package code so a dependency can't self-approve prompts. (ENG-22636)
  'Ibex',
  // Exact/Bun facades contain filesystem, process, and network convenience
  // entry points; expose them only through explicit policy endowments.
  'Exact',
  'Bun',
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

/** Collect block-lexical bindings (let/const/class/function) at one block level,
 * plus ESM `import` bindings and top-level `export` declaration bindings. Missing
 * an `import`/`export const`/`export class` binding is a real bug: a package's own
 * reference to it whose name collides with a compartment global (e.g.
 * `import fetch from 'cross-fetch'`) would be wrongly rewritten to the withheld
 * global. (ENG-22638) */
function collectBlockLexical(statements, out) {
  for (const stmt of statements || []) {
    if (!stmt) continue;
    // ESM import bindings: `import fetch from 'x'`, `import { Buffer } from 'x'`,
    // `import * as ns from 'x'` all introduce a local binding, not a free global.
    if (stmt.type === 'ImportDeclaration') {
      for (const spec of stmt.specifiers || []) {
        if (spec.local && spec.local.name) out.add(spec.local.name);
      }
      continue;
    }
    // Unwrap `export const/let/class/function ...` and `export default class/function`
    // so the exported binding name is registered.
    const s =
      stmt.type === 'ExportNamedDeclaration' || stmt.type === 'ExportDefaultDeclaration'
        ? stmt.declaration
        : stmt;
    if (!s) continue;
    if (s.type === 'VariableDeclaration' && (s.kind === 'let' || s.kind === 'const')) {
      for (const decl of s.declarations || []) collectPatternNames(decl.id, out);
    } else if (s.type === 'ClassDeclaration' && s.id) {
      out.add(s.id.name);
    } else if (s.type === 'FunctionDeclaration' && s.id) {
      out.add(s.id.name);
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
  // Depth of enclosing `with` statements. Inside a `with (obj) { ... }` body any
  // bare identifier may be a property of `obj` (statically unknowable), so we must
  // not rewrite it — doing so would resolve the name against the compartment
  // instead of the with-object. (ENG-22638)
  let withDepth = 0;

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
    // Inside a `with` body a bare name may be a property of the with-object.
    if (withDepth > 0) return;
    // A binding in any enclosing scope means this is not a free global.
    if (isBound(name)) return;
    if (name === 'eval' && rewriteEval && isCall) {
      // Direct eval → compartment-bound evaluator (indirect-eval semantics).
      replacements.push({ start: node.start, end: node.end, text: `${compartmentRef}.eval` });
      return;
    }
    if (!names.has(name)) return;
    if (name === 'globalThis' || name === 'global' || name === 'self') {
      // The self-referential globals resolve to the compartment itself.
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
      case 'WithStatement': {
        // The object expression is evaluated in the enclosing scope (its free
        // references ARE rewritten), but inside the body any bare name could be a
        // property of the object, so suppress rewriting there. (ENG-22638)
        walk(node.object, node, 'object', null);
        withDepth++;
        walk(node.body, node, 'body', null);
        withDepth--;
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
      // Key by the version-qualified identity (`name@version`) so coexisting
      // versions never share a mutable compartment object, matching the runtime
      // loader's identity. Endowment lookup still falls back to the bare name in
      // the registry (isEndowed). @ref LLP 0013#resolved-questions — (ENG-22621)
      const pkg = resolvePackage ? resolvePackage(id) : packageIdentityOfModuleId(id);
      if (!pkg) return null; // first-party / root — trusted, not compartmentalized
      // Endowment names are authored against the bare package name, so resolve
      // them by the bare selector even though the compartment key is versioned.
      const bareName = packageOfModuleId(id);
      const globalNames = endowmentsFor
        ? endowmentsFor(bareName || pkg)
        : defaultCompartmentGlobals;
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
  // Normalize Windows separators before detecting the marker: module ids can
  // carry backslashes on Windows, and a miss here misclassifies package code as
  // root-principal — which would honor its import-site grants. (ENG-22619)
  id = id.replace(/\\/g, '/');
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

const __pkgVersionMemo = new Map();

/**
 * The version-qualified identity of a module's package (`name@version`), or the
 * bare name when no version is readable. Reads the package's self-reported
 * `version` field (memoized per package root), so coexisting versions get
 * distinct compartment keys and chunk groups — matching the runtime loader's
 * identity. This distinguishes installed copies; it is not an integrity boundary
 * against a package that forges its package.json version. Bundle-time only.
 * @ref LLP 0013#resolved-questions — (ENG-22621/ENG-22768)
 */
export function packageIdentityOfModuleId(id) {
  const name = packageOfModuleId(id);
  if (!name) return null;
  const nid = String(id).replace(/\\/g, '/');
  const marker = 'node_modules/';
  const idx = nid.lastIndexOf(marker);
  if (idx === -1) return name;
  const root = nid.slice(0, idx + marker.length) + name;
  let version;
  if (__pkgVersionMemo.has(root)) {
    version = __pkgVersionMemo.get(root);
  } else {
    version = null;
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      if (manifest && typeof manifest.version === 'string') version = manifest.version;
    } catch {
      // No readable manifest/version → fall back to the bare name.
    }
    __pkgVersionMemo.set(root, version);
  }
  return version ? `${name}@${version}` : name;
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
  // @ref LLP 0014#parse-and-strip — grant attributes are build-time inputs
  // with no runtime representation; strip them FIRST, unconditionally, so
  // grant-annotated source runs in every mode and no later transform (or the
  // engine) ever sees the syntax.
  plugins.push(createImportGrantsPlugin());
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
      // @ref LLP 0014#the-grant-channel — keep symlinked dependencies
      // classifiable as dependencies in the generated graph. If Rolldown
      // realpaths an npm-link/pnpm-style edge outside node_modules, package
      // code can be misread as trusted root grant-authoring code.
      symlinks: false,
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
