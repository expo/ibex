#!/usr/bin/env node
/**
 * Generate the capability policy artifact from import-site grants.
 *
 * @ref LLP 0014#generator — walks one entry point's module graph with the
 * same Rolldown resolution the bundle uses; honors grant declarations only in
 * root-principal (non-node_modules) modules; composes them with the LLP 0013
 * request/delegation cascade; emits a reproducible, provenance-carrying
 * PolicyFile artifact. `--check` is the CI drift gate.
 *
 * Usage:
 *   generate-policy.mjs --entry <file> [--out <file>] [--mode enforce|audit]
 *   generate-policy.mjs --entry <file> [--out <file>] --check
 */
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import {
  createRolldownConfig,
  runtimeImportMetaDefine,
  packageOfModuleId,
  packageIdentityOfModuleId,
} from './transforms.mjs';
import {
  createImportGrantsPlugin,
  packageNameOfSpecifier,
  builtinSpecifierOf,
  extractImportSpecifiersDetailed,
  capabilityUnion,
  resolveCascade,
  deriveSurfaces,
  diffBuiltinAxis,
  bareNameOf,
} from './import-grants.mjs';

const args = process.argv.slice(2);
const opts = { mode: 'enforce' };
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--entry') opts.entry = args[++i];
  else if (arg === '--out') opts.out = args[++i];
  else if (arg === '--mode') opts.mode = args[++i];
  else if (arg === '--check') opts.check = true;
  else {
    console.error(`unknown argument: ${arg}`);
    process.exit(2);
  }
}

if (!opts.entry) {
  console.error(
    'Usage: generate-policy.mjs --entry <file> [--out <file>] [--mode enforce|audit] [--check]',
  );
  process.exit(2);
}

const entry = path.resolve(process.cwd(), opts.entry);
const root = path.dirname(entry);
const out = path.resolve(process.cwd(), opts.out || path.join(root, 'ibex-policy.json'));

let rolldown;
try {
  ({ rolldown } = await import('rolldown'));
} catch (err) {
  console.error('Failed to load rolldown. Run `bun install` at the repo root.');
  console.error(err?.message || err);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Collect: root-principal grant sites, package universe, package-level edges.
// ---------------------------------------------------------------------------

const rootSiteLists = []; // [{ file, sites }]
const ignoredPackageGrants = []; // supply-chain signal: grant syntax in node_modules
const generationErrors = [];
const packageDirs = new Map(); // pkg -> Set<dir>
const packageIdentities = new Set(); // version-qualified runtime selectors
const edgeTargets = new Set(); // package selectors reached by import edges
const edges = new Set(); // "fromPkg\0toPkg" ("" = root principal)
const observedBuiltins = new Map(); // package identity -> Set<node:builtin>

// Resolve an import edge's target to its version-qualified identity by walking
// the importer's node_modules chain, exactly as the bundler's resolver does.
// Edges must carry `fromIdentity -> toIdentity` (not bare names) so a delegate
// declared by one installed version can never flow along another installed
// version's import edge. @ref LLP 0014#generator (ENG-22818)
const __targetIdentityMemo = new Map();
function resolveTargetIdentity(fromModuleId, bareTarget) {
  // A root-principal importer (no node_modules ancestor) resolves from the app
  // root's node_modules.
  const start = fromModuleId
    ? path.dirname(String(fromModuleId).replace(/\\/g, '/'))
    : root;
  const memoKey = `${start}\u0000${bareTarget}`;
  if (__targetIdentityMemo.has(memoKey)) return __targetIdentityMemo.get(memoKey);
  let dir = start;
  let result = bareTarget;
  for (;;) {
    const candidate = path.join(dir, 'node_modules', bareTarget);
    if (existsSync(path.join(candidate, 'package.json'))) {
      result = packageIdentityOfModuleId(path.join(candidate, 'index.js')) || bareTarget;
      break;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  __targetIdentityMemo.set(memoKey, result);
  return result;
}

// Record a package-level import edge as `fromIdentity -> toIdentity`. Root
// edges (no node_modules ancestor) carry `''` on the from side and are dropped
// before the cascade — they grant via rootGrants, not delegates.
function recordEdge(fromModuleId, bareTarget) {
  edgeTargets.add(bareTarget);
  const fromIdentity = packageIdentityOfModuleId(fromModuleId) || '';
  const toIdentity = resolveTargetIdentity(fromModuleId, bareTarget);
  if (fromIdentity !== toIdentity) edges.add(`${fromIdentity}\u0000${toIdentity}`);
}

// @ref LLP 0014#the-grant-channel — grants are honored only in modules that
// belong to the trusted root principal (no node_modules ancestor). The same
// syntax inside a package confers nothing and is surfaced loudly.
const collector = createImportGrantsPlugin({
  collect(id, parsed) {
    const pkg = packageOfModuleId(id);
    if (pkg === null) {
      rootSiteLists.push({ file: id, sites: parsed.sites });
      generationErrors.push(...parsed.errors);
    } else if (parsed.sites.length) {
      ignoredPackageGrants.push({ package: pkg, file: id, sites: parsed.sites });
    }
  },
});

const graphPlugin = {
  name: 'import-grants-graph',
  resolveId(specifier, importer) {
    if (!importer) return null;
    const to = packageNameOfSpecifier(specifier);
    if (!to) return null;
    recordEdge(importer, to);
    return null; // observe only; default resolution proceeds
  },
  transform(code, id) {
    const pkg = packageOfModuleId(id);
    const extracted = extractImportSpecifiersDetailed(code);
    if (!extracted.parseable && pkg) {
      generationErrors.push({
        message:
          'unable to parse package module for import-policy analysis; refusing to under-generate builtins/packages',
        file: id,
        line: 0,
      });
      return null;
    }
    for (const spec of extracted.specifiers) {
      const to = packageNameOfSpecifier(spec);
      if (to) recordEdge(id, to);
    }
    if (pkg) {
      const identity = packageIdentityOfModuleId(id) || pkg;
      packageIdentities.add(identity);
      if (!packageDirs.has(pkg)) packageDirs.set(pkg, new Set());
      // Normalize backslashes to agree with packageOfModuleId (ENG-22619): on
      // Windows the raw id uses `\`, so an un-normalized scan misses the marker
      // and silently drops the package's directory (hence its ibex manifest).
      const nid = id.replace(/\\/g, '/');
      const marker = 'node_modules/';
      const idx = nid.lastIndexOf(marker);
      if (idx !== -1) packageDirs.get(pkg).add(nid.slice(0, idx + marker.length) + pkg);

      // @ref LLP 0014#the-generated-artifact — observe each package module's
      // static builtin imports so the emitted `builtins` list is a true
      // containment statement (default-deny) rather than an omitted free pass.
      // Done here rather than in resolveId because rolldown pre-marks builtins
      // external and skips the resolve hook for them, but transform still sees
      // the source. A computed specifier (`require(n)`) contributes nothing and
      // is therefore denied at runtime (fail closed).
      for (const spec of extracted.specifiers) {
        const builtin = builtinSpecifierOf(spec);
        if (builtin) {
          if (!observedBuiltins.has(identity)) observedBuiltins.set(identity, new Set());
          observedBuiltins.get(identity).add(builtin);
        }
      }
    }
    return null;
  },
};

const config = createRolldownConfig({
  input: entry,
  treeshake: false,
  keepRelativeCjsExternal: false,
  define: runtimeImportMetaDefine,
  compartments: false,
});
// The collector must see modules BEFORE the shared pipeline's strip pass.
config.plugins = [collector, graphPlugin, ...config.plugins];

const bundle = await rolldown(config);
await bundle.generate({ format: 'cjs', exports: 'auto', codeSplitting: false });
if (typeof bundle.close === 'function') await bundle.close();

if (generationErrors.length) {
  for (const err of generationErrors) {
    console.error(`error: ${err.message} (${path.relative(root, err.file)}:${err.line})`);
  }
  process.exit(2);
}

for (const target of edgeTargets) {
  if (!packageDirs.has(target)) {
    generationErrors.push({
      message: `package "${target}" is reachable but no module source was analyzed for import policy`,
      file: entry,
      line: 0,
    });
  }
}

if (generationErrors.length) {
  for (const err of generationErrors) {
    const where = err.line ? `${path.relative(root, err.file)}:${err.line}` : path.relative(root, err.file);
    console.error(`error: ${err.message} (${where})`);
  }
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Requests: `ibex` manifests from every reachable package (LLP 0013 cascade).
// ---------------------------------------------------------------------------

// @ref LLP 0013#delegation-and-authority-flow — each installed version's `ibex`
// manifest is recorded under its own identity, NOT merged under the bare name,
// so one version's `delegates` can never flow along another version's import
// edge (the ENG-22818 defect). (ENG-22818)
const requests = new Map(); // identity -> { capabilities: [], delegates: { dep: [caps] } }
for (const [pkg, dirs] of packageDirs) {
  for (const dir of dirs) {
    let manifest;
    try {
      manifest = JSON.parse(await fs.readFile(path.join(dir, 'package.json'), 'utf8'));
    } catch {
      continue;
    }
    const ibex = manifest?.ibex;
    if (!ibex || typeof ibex !== 'object') continue;
    const identity = packageIdentityOfModuleId(path.join(dir, 'index.js')) || pkg;
    let entry = requests.get(identity);
    if (!entry) {
      entry = { capabilities: [], delegates: {} };
      requests.set(identity, entry);
    }
    if (Array.isArray(ibex.capabilities)) {
      entry.capabilities.push(...ibex.capabilities.filter((c) => typeof c === 'string'));
    }
    if (ibex.delegates && typeof ibex.delegates === 'object') {
      for (const [dep, caps] of Object.entries(ibex.delegates)) {
        if (!Array.isArray(caps)) continue;
        entry.delegates[dep] = [
          ...(entry.delegates[dep] || []),
          ...caps.filter((c) => typeof c === 'string'),
        ];
      }
    }
  }
}
for (const [identity, entry] of [...requests]) {
  if (!entry.capabilities.length && !Object.keys(entry.delegates).length) {
    requests.delete(identity);
  }
}

// ---------------------------------------------------------------------------
// Root grants (union across sites) + explicit surfaces + also-exceptions.
// ---------------------------------------------------------------------------

const rootGrants = new Map(); // pkg -> [{ capability, site, via? }]
const explicitSurfaces = new Map(); // pkg -> { endow: Set, builtins: Set }

function surfacesFor(pkg) {
  if (!explicitSurfaces.has(pkg)) {
    explicitSurfaces.set(pkg, { endow: new Set(), builtins: new Set() });
  }
  return explicitSurfaces.get(pkg);
}

function addRootGrant(pkg, capability, site, via) {
  if (!rootGrants.has(pkg)) rootGrants.set(pkg, []);
  rootGrants.get(pkg).push({ capability, site, ...(via ? { via } : {}) });
}

rootSiteLists.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
for (const { file, sites } of rootSiteLists) {
  const rel = path.relative(root, file);
  for (const site of sites) {
    const where = `${rel}:${site.line}`;
    for (const cap of site.capabilities) addRootGrant(site.package, cap, where);
    for (const name of site.endow) surfacesFor(site.package).endow.add(name);
    for (const name of site.builtins) surfacesFor(site.package).builtins.add(name);
    // @ref LLP 0014#transitive-grants-and-co-located-exceptions — an `also:`
    // grant is app-wide ambient authority for the named package; the edge
    // association is provenance and GC linkage, not enforcement.
    for (const [alsoPkg, caps] of Object.entries(site.also)) {
      for (const cap of caps) addRootGrant(alsoPkg, cap, where, 'also');
    }
  }
}

const sortedEdges = [...edges]
  .sort()
  .map((e) => e.split('\u0000'))
  .filter(([from]) => from !== '') // root edges carry grants via rootGrants, not delegates
  .map(([from, to]) => [from, to]);

// Seed each bare import-site grant into every installed identity of that name:
// an import-site grant is app-wide for the package it names, so any version may
// carry it (and, if that version declares a matching edge + delegate, forward
// it). The cascade then runs entirely on identities; delegate dictionaries stay
// bare-keyed (that is how a manifest authors them), so `bareNameOf` maps an
// identity edge target back to the delegate name. (ENG-22818)
const identitiesByName = new Map();
for (const id of packageIdentities) {
  const bare = bareNameOf(id);
  if (!identitiesByName.has(bare)) identitiesByName.set(bare, new Set());
  identitiesByName.get(bare).add(id);
}
const rootGrantsByIdentity = new Map();
for (const [pkg, grants] of rootGrants) {
  const ids = identitiesByName.get(pkg);
  if (ids && ids.size) {
    for (const id of ids) rootGrantsByIdentity.set(id, grants);
  } else {
    // An `also:` target that is never imported has no analyzed module (hence no
    // identity); keep its grant under the bare name it was authored with.
    rootGrantsByIdentity.set(pkg, grants);
  }
}

const effectiveByHolder = resolveCascade({
  rootGrants: rootGrantsByIdentity,
  edges: sortedEdges,
  requests,
  bareOf: bareNameOf,
});

// Route each resolved capability to the selector it is emitted under. An
// import-site/root grant (site provenance) is app-wide and belongs under the
// bare name — matching the runtime's bare-name fall-through. A delegated
// capability (delegate provenance) is version-scoped and belongs under the
// receiving identity, so it cannot leak to a coexisting version of the same
// dependency. (ENG-22818)
const effective = new Map(); // outputKey -> Map<capability, provenance>
for (const [holder, caps] of effectiveByHolder) {
  for (const [cap, why] of caps) {
    const key = why && why.delegate !== undefined ? holder : bareNameOf(holder);
    let m = effective.get(key);
    if (!m) {
      m = new Map();
      effective.set(key, m);
    }
    if (!m.has(cap)) m.set(cap, why);
  }
}

// ---------------------------------------------------------------------------
// Artifact assembly (reproducible: sorted keys, relative paths, no timestamps).
// ---------------------------------------------------------------------------

const universe = new Set([
  ...packageDirs.keys(),
  ...packageIdentities,
  ...edgeTargets,
  ...rootGrants.keys(),
  ...effective.keys(),
  ...observedBuiltins.keys(),
]);

const packagesOut = {};
const provenanceOut = {};
for (const pkg of [...universe].sort()) {
  const caps = capabilityUnion([...(effective.get(pkg)?.keys() ?? [])]);
  const derived = deriveSurfaces(caps);
  const explicit = explicitSurfaces.get(pkg);
  const endow = [...new Set([...derived.endow, ...(explicit ? explicit.endow : [])])].sort();
  const observed = observedBuiltins.get(pkg);
  const builtins = [
    ...new Set([
      ...derived.builtins,
      ...(explicit ? explicit.builtins : []),
      ...(observed ? observed : []),
    ]),
  ].sort();

  // @ref LLP 0014#the-generated-artifact — every package in the analyzed
  // graph appears, granted or not; the empty entry is the containment
  // statement, and a missing package is a generation bug.
  //
  // `builtins` is emitted UNCONDITIONALLY (even when empty) for every generated
  // package entry (ENG-22683): the runtime reads an *absent* `builtins` as
  // "unrestricted on the import axis", so an omitted field would leave `os`,
  // `child_process`, etc. reachable by default and make the empty entry a free
  // pass instead of a containment statement. The list is the builtins the
  // package actually imports in this graph (statically observed) plus any
  // authored `builtins:` — so a package that imports nothing gets `[]`
  // (deny-all builtins) while one that imports `os` gets `["node:os"]`. Absence
  // is reserved for hand-authored policies; the generator never omits it. `endow`
  // stays conditional (absent endow is already closed-by-default in the runtime).
  const entryOut = {};
  if (caps.length) entryOut.capabilities = caps;
  if (endow.length) entryOut.endow = endow;
  entryOut.builtins = builtins;
  packagesOut[pkg] = entryOut;

  const whys = effective.get(pkg);
  if (whys && whys.size) {
    provenanceOut[pkg] = [...whys.entries()]
      .map(([capability, why]) => ({ capability, ...why }))
      .sort((a, b) =>
        (a.capability + (a.site || '') + (a.via || '')).localeCompare(
          b.capability + (b.site || '') + (b.via || ''),
        ),
      );
  }
}

const artifact = {
  generated: {
    version: 1,
    tool: 'generate-policy.mjs',
    entry: path.relative(root, entry) || path.basename(entry),
  },
  mode: opts.mode,
  packages: packagesOut,
  provenance: provenanceOut,
};
const rendered = `${JSON.stringify(artifact, null, 2)}\n`;

for (const ignored of ignoredPackageGrants) {
  const rel = path.relative(root, ignored.file);
  for (const site of ignored.sites) {
    console.error(
      `warning: grant attribute in package code is not a grant channel and was ignored: ` +
        `"${ignored.package}" at ${rel}:${site.line} (requests belong in package.json "ibex")`,
    );
  }
}

// ---------------------------------------------------------------------------
// Emit, or check for drift.
// ---------------------------------------------------------------------------

function capsByPackage(artifactJson) {
  const map = new Map();
  for (const [pkg, entryOut] of Object.entries(artifactJson.packages || {})) {
    map.set(pkg, new Set(entryOut.capabilities || []));
  }
  return map;
}

if (opts.check) {
  // @ref LLP 0014#the-generated-artifact — the committed artifact is
  // drift-checked; expansions are the review tripwire, shrinkage is free.
  let existing;
  try {
    existing = await fs.readFile(out, 'utf8');
  } catch {
    console.error(`policy artifact missing: ${out}\nrun: generate-policy.mjs --entry ${opts.entry}`);
    process.exit(1);
  }
  if (existing === rendered) {
    console.log(`policy artifact up to date: ${path.relative(process.cwd(), out)}`);
    process.exit(0);
  }
  console.error(`policy artifact is stale: ${path.relative(process.cwd(), out)}`);
  try {
    const existingJson = JSON.parse(existing);
    // Diff the declared mode too: a policy generated with `--mode audit` drifts
    // against an enforce-default regeneration on the `mode` field alone, which the
    // capability diff below can't see — surface it explicitly so the fix (pass the
    // matching `--mode` to `check`) is obvious rather than "structural changes
    // only". (ENG-22642)
    const oldMode = existingJson.mode ?? '(unset)';
    const newMode = artifact.mode ?? '(unset)';
    const modeChanged = oldMode !== newMode;
    const oldCaps = capsByPackage(existingJson);
    const newCaps = capsByPackage(artifact);
    const expansions = [];
    const shrinkage = [];
    for (const [pkg, caps] of newCaps) {
      for (const cap of caps) {
        if (!oldCaps.get(pkg)?.has(cap)) expansions.push(`${pkg}: ${cap}`);
      }
    }
    for (const [pkg, caps] of oldCaps) {
      for (const cap of caps) {
        if (!newCaps.get(pkg)?.has(cap)) shrinkage.push(`${pkg}: ${cap}`);
      }
    }
    // Import (builtins) axis drift, with the omitted=unrestricted `*` sentinel
    // so a tightening isn't misreported as an expansion (ENG-22701).
    const builtinDrift = diffBuiltinAxis(existingJson.packages, artifact.packages);
    expansions.push(...builtinDrift.expansions);
    shrinkage.push(...builtinDrift.shrinkage);
    if (modeChanged) {
      console.error(
        `mode changed: ${oldMode} -> ${newMode} ` +
          `(if intentional, run check with --mode ${oldMode})`
      );
    }
    if (expansions.length) {
      console.error('policy EXPANSIONS (review these):');
      for (const line of expansions) console.error(`  + ${line}`);
    }
    if (shrinkage.length) {
      console.error('policy shrinkage:');
      for (const line of shrinkage) console.error(`  - ${line}`);
    }
    if (!expansions.length && !shrinkage.length && !modeChanged) {
      console.error('(structural changes only — packages, surfaces, or provenance)');
    }
  } catch (err) {
    if (err instanceof SyntaxError) {
      console.error('(existing artifact is not valid JSON)');
    } else {
      console.error(`policy artifact validation error: ${err?.message || err}`);
    }
  }
  console.error(`run: generate-policy.mjs --entry ${opts.entry} --out ${opts.out || out}`);
  process.exit(1);
}

await fs.writeFile(out, rendered);
const granted = Object.values(packagesOut).filter((p) => p.capabilities?.length).length;
console.log(
  `wrote ${path.relative(process.cwd(), out)}: ${universe.size} package(s), ` +
    `${granted} with grants, mode=${opts.mode}`,
);
