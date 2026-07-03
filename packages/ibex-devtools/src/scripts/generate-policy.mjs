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
import path from 'path';
import {
  createRolldownConfig,
  runtimeImportMetaDefine,
  packageOfModuleId,
} from './transforms.mjs';
import {
  createImportGrantsPlugin,
  packageNameOfSpecifier,
  capabilityUnion,
  resolveCascade,
  deriveSurfaces,
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
const edges = new Set(); // "fromPkg\0toPkg" ("" = root principal)

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
    const from = packageOfModuleId(importer);
    if (from !== to) edges.add(`${from ?? ''}\u0000${to}`);
    return null; // observe only; default resolution proceeds
  },
  transform(code, id) {
    const pkg = packageOfModuleId(id);
    if (pkg) {
      if (!packageDirs.has(pkg)) packageDirs.set(pkg, new Set());
      // Normalize backslashes to agree with packageOfModuleId (ENG-22619): on
      // Windows the raw id uses `\`, so an un-normalized scan misses the marker
      // and silently drops the package's directory (hence its ibex manifest).
      const nid = id.replace(/\\/g, '/');
      const marker = 'node_modules/';
      const idx = nid.lastIndexOf(marker);
      if (idx !== -1) packageDirs.get(pkg).add(nid.slice(0, idx + marker.length) + pkg);
    }
    return null;
  },
};

const config = createRolldownConfig({
  input: entry,
  treeshake: false,
  keepRelativeCjsExternal: true,
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

// ---------------------------------------------------------------------------
// Requests: `ibex` manifests from every reachable package (LLP 0013 cascade).
// ---------------------------------------------------------------------------

const requests = new Map(); // pkg -> { capabilities: [], delegates: { dep: [caps] } }
for (const [pkg, dirs] of packageDirs) {
  const merged = { capabilities: [], delegates: {} };
  for (const dir of dirs) {
    let manifest;
    try {
      manifest = JSON.parse(await fs.readFile(path.join(dir, 'package.json'), 'utf8'));
    } catch {
      continue;
    }
    const ibex = manifest?.ibex;
    if (!ibex || typeof ibex !== 'object') continue;
    if (Array.isArray(ibex.capabilities)) {
      merged.capabilities.push(...ibex.capabilities.filter((c) => typeof c === 'string'));
    }
    if (ibex.delegates && typeof ibex.delegates === 'object') {
      for (const [dep, caps] of Object.entries(ibex.delegates)) {
        if (!Array.isArray(caps)) continue;
        merged.delegates[dep] = [
          ...(merged.delegates[dep] || []),
          ...caps.filter((c) => typeof c === 'string'),
        ];
      }
    }
  }
  if (merged.capabilities.length || Object.keys(merged.delegates).length) {
    requests.set(pkg, merged);
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

const effective = resolveCascade({ rootGrants, edges: sortedEdges, requests });

// ---------------------------------------------------------------------------
// Artifact assembly (reproducible: sorted keys, relative paths, no timestamps).
// ---------------------------------------------------------------------------

const universe = new Set([
  ...packageDirs.keys(),
  ...rootGrants.keys(),
  ...effective.keys(),
]);

const packagesOut = {};
const provenanceOut = {};
for (const pkg of [...universe].sort()) {
  const caps = capabilityUnion([...(effective.get(pkg)?.keys() ?? [])]);
  const derived = deriveSurfaces(caps);
  const explicit = explicitSurfaces.get(pkg);
  const endow = [...new Set([...derived.endow, ...(explicit ? explicit.endow : [])])].sort();
  const builtins = [
    ...new Set([...derived.builtins, ...(explicit ? explicit.builtins : [])]),
  ].sort();

  // @ref LLP 0014#the-generated-artifact — every package in the analyzed
  // graph appears, granted or not; the empty entry is the containment
  // statement, and a missing package is a generation bug.
  const entryOut = {};
  if (caps.length) entryOut.capabilities = caps;
  if (endow.length) entryOut.endow = endow;
  if (builtins.length) entryOut.builtins = builtins;
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
    if (modeChanged) {
      console.error(
        `mode changed: ${oldMode} -> ${newMode} ` +
          `(if intentional, run check with --mode ${oldMode})`
      );
    }
    if (expansions.length) {
      console.error('capability EXPANSIONS (review these):');
      for (const line of expansions) console.error(`  + ${line}`);
    }
    if (shrinkage.length) {
      console.error('capability shrinkage:');
      for (const line of shrinkage) console.error(`  - ${line}`);
    }
    if (!expansions.length && !shrinkage.length && !modeChanged) {
      console.error('(structural changes only — packages, surfaces, or provenance)');
    }
  } catch {
    console.error('(existing artifact is not valid JSON)');
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
