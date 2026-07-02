/**
 * Import-site capability grants: parse, strip, capability set algebra, and
 * the delegation cascade.
 *
 * @ref LLP 0014#grant-syntax — grants are import attributes with string
 * values (standard grammar); they are declarative build inputs compiled into
 * the generated policy artifact and stripped before the engine sees them.
 * Parsing is fail-closed: a malformed grant string is an error, not a skip.
 */
import { parse } from 'acorn';

/** Attribute keys this layer owns. Anything else (e.g. `type`) passes through. */
export const GRANT_ATTRIBUTE_KEYS = Object.freeze([
  'grants',
  'endow',
  'builtins',
  'also',
]);

function parseModule(source, { locations = false } = {}) {
  try {
    return parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      locations,
      ranges: true,
    });
  } catch {
    // Script sources have no import declarations, hence no attributes.
    return null;
  }
}

function applyReplacements(source, replacements) {
  if (!replacements.length) return source;
  replacements.sort((a, b) => b.start - a.start);
  let out = source;
  for (const r of replacements) {
    out = out.slice(0, r.start) + r.text + out.slice(r.end);
  }
  return out;
}

function attributeKeyName(attr) {
  return attr.key.type === 'Identifier' ? attr.key.name : String(attr.key.value);
}

/**
 * Derive the package selector a bare specifier resolves to, or null when the
 * specifier is not a package (relative/absolute path, builtin). Subpaths are
 * folded onto the package: `lodash/fp` → `lodash`, `@scope/pkg/x` → `@scope/pkg`.
 */
export function packageNameOfSpecifier(specifier) {
  if (typeof specifier !== 'string' || specifier.length === 0) return null;
  if (specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('\0')) {
    return null;
  }
  if (specifier.startsWith('node:')) return null;
  const parts = specifier.split('/');
  if (parts[0].startsWith('@')) {
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return parts[0];
}

function parseNameList(raw) {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function isWellFormedCapability(cap) {
  // One token, no whitespace, none of the `also:` metacharacters.
  return /^[^\s;]+$/.test(cap) && !cap.includes('=>');
}

function parseCapabilityList(raw, errors, file, line) {
  const caps = [];
  for (const cap of parseNameList(raw)) {
    if (!isWellFormedCapability(cap)) {
      errors.push({
        message: `malformed capability "${cap}" in grants list`,
        file,
        line,
      });
      continue;
    }
    caps.push(cap);
  }
  return caps;
}

/**
 * `also` grammar: `pkg => cap, cap; pkg2 => cap`.
 * @ref LLP 0014#transitive-grants-and-co-located-exceptions
 */
function parseAlsoList(raw, errors, file, line) {
  const out = Object.create(null);
  for (const entry of raw.split(';').map((s) => s.trim()).filter(Boolean)) {
    const arrow = entry.indexOf('=>');
    if (arrow === -1) {
      errors.push({ message: `malformed also entry "${entry}" (expected "pkg => cap, cap")`, file, line });
      continue;
    }
    const pkg = entry.slice(0, arrow).trim();
    if (!pkg || packageNameOfSpecifier(pkg) !== pkg) {
      errors.push({ message: `malformed package name "${pkg}" in also entry`, file, line });
      continue;
    }
    const caps = parseCapabilityList(entry.slice(arrow + 2), errors, file, line);
    if (!caps.length) continue;
    out[pkg] = [...(out[pkg] || []), ...caps];
  }
  return out;
}

/**
 * Parse the grant declarations in one module's source.
 *
 * Returns `{ sites, errors }`. Each site:
 *   { package, specifier, line, capabilities, endow, builtins, also }
 *
 * Fail-closed properties — @ref LLP 0014#grant-syntax — normative rules:
 *  - a grant attribute whose value is not a string literal is unreachable by
 *    grammar (acorn rejects it), so everything here is statically evaluable;
 *  - malformed grant/also strings produce `errors`, never silent skips;
 *  - grant attributes on a non-package specifier (relative path, `node:`
 *    builtin) are errors — grants attach to package selectors only.
 */
export function parseImportGrants(source, filePath = '<module>') {
  const result = { sites: [], errors: [] };
  if (!source || source.indexOf('with') === -1) return result;
  const ast = parseModule(source, { locations: true });
  if (!ast) return result;

  for (const node of ast.body) {
    const attrs = node.attributes || [];
    if (!attrs.length || !node.source) continue;
    const line = node.loc ? node.loc.start.line : 0;
    const site = {
      package: null,
      specifier: node.source.value,
      line,
      capabilities: [],
      endow: [],
      builtins: [],
      also: Object.create(null),
    };
    let sawGrantKey = false;
    for (const attr of attrs) {
      const key = attributeKeyName(attr);
      if (!GRANT_ATTRIBUTE_KEYS.includes(key)) continue;
      sawGrantKey = true;
      const raw = attr.value && attr.value.value;
      if (typeof raw !== 'string') {
        result.errors.push({ message: `attribute "${key}" must be a string literal`, file: filePath, line });
        continue;
      }
      if (key === 'grants') {
        site.capabilities.push(...parseCapabilityList(raw, result.errors, filePath, line));
      } else if (key === 'endow') {
        site.endow.push(...parseNameList(raw));
      } else if (key === 'builtins') {
        site.builtins.push(...parseNameList(raw));
      } else if (key === 'also') {
        const also = parseAlsoList(raw, result.errors, filePath, line);
        for (const [pkg, caps] of Object.entries(also)) {
          site.also[pkg] = [...(site.also[pkg] || []), ...caps];
        }
      }
    }
    if (!sawGrantKey) continue;
    const pkg = packageNameOfSpecifier(node.source.value);
    if (!pkg) {
      result.errors.push({
        message: `grant attributes on non-package specifier "${node.source.value}" (grants attach to package selectors)`,
        file: filePath,
        line,
      });
      continue;
    }
    site.package = pkg;
    result.sites.push(site);
  }
  return result;
}

/**
 * Remove the grant attribute keys from every import/re-export `with` clause,
 * preserving unrecognized attributes (`type: "json"`). Grants have no runtime
 * representation — the engine never sees the syntax.
 * @ref LLP 0014#parse-and-strip
 */
export function stripGrantAttributes(source) {
  if (!source || source.indexOf('with') === -1) return source;
  const ast = parseModule(source);
  if (!ast) return source;

  const replacements = [];
  for (const node of ast.body) {
    const attrs = node.attributes || [];
    if (!attrs.length || !node.source) continue;
    const kept = attrs.filter((a) => !GRANT_ATTRIBUTE_KEYS.includes(attributeKeyName(a)));
    if (kept.length === attrs.length) continue;
    // The with-clause span runs from the end of the source string literal to
    // the `}` closing the attribute list.
    const braceEnd = source.indexOf('}', attrs[attrs.length - 1].end);
    if (braceEnd === -1) continue;
    const text = kept.length
      ? ` with { ${kept.map((a) => source.slice(a.start, a.end)).join(', ')} }`
      : '';
    replacements.push({ start: node.source.end, end: braceEnd + 1, text });
  }
  return applyReplacements(source, replacements);
}

// ===========================================================================
// Capability set algebra
// ===========================================================================
//
// @ref LLP 0014#set-algebra-and-cascade — capabilities are `:`-separated
// segment paths (`fs:read:/app/images`); a shorter path subsumes its
// extensions, `*` matches any segment, and a trailing `/**` on a path
// parameter subsumes deeper paths. The authoritative matcher is the Rust
// `CapabilityManager`; this algebra is deliberately conservative — an
// intersection it cannot prove is dropped (fail closed, never over-grant).

function pathPrefixMatch(pattern, value) {
  if (!pattern.endsWith('/**')) return false;
  const base = pattern.slice(0, -3);
  if (value === base) return true;
  return value.startsWith(base.endsWith('/') ? base : `${base}/`);
}

/** True when grant `a` covers everything grant `b` covers. */
export function capabilitySubsumes(a, b) {
  if (a === b) return true;
  const as = a.split(':');
  const bs = b.split(':');
  if (as.length > bs.length) return false;
  for (let i = 0; i < as.length; i++) {
    if (as[i] === '*') continue;
    if (as[i] !== bs[i]) {
      // Path parameters live in the final segment: `fs:read:/a/**` ⊇ `fs:read:/a/b`.
      return i === as.length - 1 && pathPrefixMatch(as[i], bs.slice(i).join(':'));
    }
  }
  return true;
}

/** The narrower of two grants when comparable, else null (disjoint → dropped). */
export function capabilityIntersect(a, b) {
  if (capabilitySubsumes(a, b)) return b;
  if (capabilitySubsumes(b, a)) return a;
  return null;
}

/** Deduplicated, subsumption-minimized, sorted capability list. */
export function capabilityUnion(caps) {
  const list = [...new Set(caps.filter(Boolean))].sort();
  return list.filter((c) => !list.some((o) => o !== c && capabilitySubsumes(o, c)));
}

// ===========================================================================
// Delegation cascade
// ===========================================================================

/**
 * Resolve ambient authority for every package:
 *
 *   effective(p) = rootGrants(p) ∪ ⋃ over edges q→p:
 *                    capabilityIntersect(delegates(q→p), effective(q))
 *
 * @ref LLP 0013#delegation-and-authority-flow — requests/delegates never
 * grant by themselves; the root grants (import sites) are the sole grant
 * root and delegation only attenuates. Monotone fixpoint: every added
 * capability is one of the finitely many strings appearing in the inputs,
 * so iteration terminates.
 *
 * Inputs:
 *  - rootGrants: Map pkg → [{ capability, site, via? }]
 *  - edges:      [[fromPkg, toPkg], ...] package-level import edges
 *  - requests:   Map pkg → { capabilities?: [], delegates?: { dep: [caps] } }
 *
 * Returns Map pkg → Map capability → provenance
 * (provenance: { site, via? } for root grants; { via: fromPkg, delegate } for
 * cascaded ones — the chain that produced each capability).
 */
export function resolveCascade({ rootGrants = new Map(), edges = [], requests = new Map() } = {}) {
  const effective = new Map();
  const add = (pkg, cap, why) => {
    let caps = effective.get(pkg);
    if (!caps) {
      caps = new Map();
      effective.set(pkg, caps);
    }
    // A capability already covered adds no authority — skip it so provenance
    // stays signal (and cascade cycles converge without redundant entries).
    for (const existing of caps.keys()) {
      if (capabilitySubsumes(existing, cap)) return false;
    }
    caps.set(cap, why);
    return true;
  };

  for (const [pkg, grants] of rootGrants) {
    for (const g of grants) {
      add(pkg, g.capability, { site: g.site, ...(g.via ? { via: g.via } : {}) });
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [from, to] of edges) {
      const delegated = requests.get(from)?.delegates?.[to];
      const fromCaps = effective.get(from);
      if (!delegated || !fromCaps) continue;
      for (const d of delegated) {
        for (const e of fromCaps.keys()) {
          const x = capabilityIntersect(d, e);
          if (x != null && add(to, x, { via: from, delegate: d })) changed = true;
        }
      }
    }
  }
  return effective;
}

// ===========================================================================
// Surface derivation
// ===========================================================================

/**
 * Derive companion endowments/builtins from capability grants so a usable
 * policy doesn't require authoring all three surfaces by hand. Explicit
 * `endow:`/`builtins:` attributes extend this set. Deliberately small; this
 * table is the single source. @ref LLP 0014#surface-derivation
 */
export function deriveSurfaces(capabilities) {
  const endow = new Set();
  const builtins = new Set();
  for (const cap of capabilities) {
    const cls = cap.split(':')[0];
    if (cls === 'network') {
      endow.add('fetch');
      endow.add('XMLHttpRequest');
      endow.add('WebSocket');
    } else if (cls === 'process') {
      endow.add('process');
    } else if (cls === 'fs') {
      builtins.add('node:fs');
      builtins.add('node:fs/promises');
      builtins.add('node:path');
    }
  }
  return { endow: [...endow].sort(), builtins: [...builtins].sort() };
}

// ===========================================================================
// Bundler plugin
// ===========================================================================

/**
 * Rolldown-style plugin that strips grant attributes from every module so
 * grant-annotated source is runnable in all modes (the engine never sees the
 * syntax). With a `collect` callback it doubles as the generator's collector:
 * `collect(id, parsed)` receives the parse BEFORE stripping, for every module
 * that carries grant keys. Runs before all other transforms.
 * @ref LLP 0014#parse-and-strip
 */
export function createImportGrantsPlugin({ name = 'import-grants', collect } = {}) {
  return {
    name,
    transform(code, id) {
      if (!code || code.indexOf('with') === -1) return null;
      if (collect) {
        const parsed = parseImportGrants(code, id);
        if (parsed.sites.length || parsed.errors.length) collect(id, parsed);
      }
      const stripped = stripGrantAttributes(code);
      if (stripped === code) return null;
      return { code: stripped };
    },
  };
}
