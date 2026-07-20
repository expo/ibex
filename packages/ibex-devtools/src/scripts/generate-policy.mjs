#!/usr/bin/env node
/**
 * Generate the capability policy artifact from import-site grants.
 *
 * @ref LLP 0014#generator — walks one entry point's module graph with the
 * same Rolldown resolution the bundle uses; honors grant declarations only in
 * root-principal (non-node_modules) modules; composes them with the LLP 0013
 * request/delegation cascade; emits a reproducible, provenance-carrying
 * canonical typed policy artifact. `--check` is the CI drift gate.
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
  bareNameOf,
} from './import-grants.mjs';
import {
  assertTypedAuthority,
  buildCanonicalPolicy,
  classifyPolicyDrift,
  compareCanonicalBytes,
  packageIntegrity,
  resolveTypedDelegations,
  withV1CwdObserveFloor,
} from './capsec-policy-authoring.mjs';
import {
  authenticateAnalyzedPackageTree,
  packageRelativeModulePath,
  packageRootForModuleId,
} from './policy-package-snapshot.mjs';
import { canonicalJson, computeDomainDigest } from './capsec-contract.mjs';
import {
  computeAuthenticatedGraphIdentityV1,
  decodeCanonicalSourceId,
  encodeCanonicalSourceId,
  validateAuthenticatedGraphSnapshotV1,
} from './authenticated-graph-snapshot.mjs';

const args = process.argv.slice(2);
const opts = { mode: 'enforce' };
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--entry') opts.entry = args[++i];
  else if (arg === '--out') opts.out = args[++i];
  else if (arg === '--mode') opts.mode = args[++i];
  else if (arg === '--target-profile') opts.targetProfile = args[++i];
  else if (arg === '--target-triple') opts.targetTriple = args[++i];
  else if (arg === '--mount-profile') opts.mountProfile = args[++i];
  else if (arg === '--authenticated-graph-snapshot') opts.authenticatedGraphSnapshot = args[++i];
  else if (arg === '--check') opts.check = true;
  else {
    console.error(`unknown argument: ${arg}`);
    process.exit(2);
  }
}

if (!opts.entry) {
  console.error(
    'Usage: generate-policy.mjs --entry <file> [--out <file>] [--target-profile <profile>] [--target-triple <triple>] [--mount-profile <profile>] [--mode enforce|audit] [--check]',
  );
  process.exit(2);
}
if (opts.mode !== 'enforce') {
  console.error('canonical production policy is enforce-only; use the separate capsec audit workflow');
  process.exit(2);
}

const entry = path.resolve(process.cwd(), opts.entry);
async function discoverProjectRoot(entryFile) {
  let cursor = path.dirname(entryFile);
  for (;;) {
    if (existsSync(path.join(cursor, 'package.json'))) return cursor;
    const parent = path.dirname(cursor);
    if (parent === cursor) return path.dirname(entryFile);
    cursor = parent;
  }
}
const root = await discoverProjectRoot(entry);
const entryRelative = path.relative(root, entry).split(path.sep).join('/');
if (!entryRelative || entryRelative.startsWith('../') || path.isAbsolute(entryRelative)) {
  console.error('policy entry must be inside the discovered project root');
  process.exit(2);
}
const targetProfile = opts.targetTriple
  ? { kind: 'compiled', profile: opts.targetProfile || 'sfe-v1', targetTriple: opts.targetTriple }
  : { kind: 'source', profile: opts.targetProfile || 'portable-v1' };
const mountProfile = opts.mountProfile ||
  (targetProfile.kind === 'compiled' ? 'compiled-app-work-v1' : 'project-v1');
const artifactKey = [
  entryRelative.replace(/[^a-zA-Z0-9._-]+/g, '_'),
  targetProfile.profile,
  targetProfile.targetTriple,
  mountProfile,
].filter(Boolean).join('.');
const out = path.resolve(
  process.cwd(),
  opts.out || path.join(root, `ibex-policy.${artifactKey}.json`),
);
const rootManifestPath = path.join(root, 'package.json');
const rootManifest = existsSync(rootManifestPath)
  ? JSON.parse(await fs.readFile(rootManifestPath, 'utf8'))
  : {};
const rootIbex = rootManifest?.ibex && typeof rootManifest.ibex === 'object'
  ? rootManifest.ibex
  : {};
const authoredCandidateSites = rootIbex.computedCandidates?.sites || [];
if (!Array.isArray(authoredCandidateSites)) {
  throw new TypeError('package.json ibex.computedCandidates.sites must be an array');
}
const candidateDeclarations = authoredCandidateSites.map((site, index) => {
  if (!site || typeof site !== 'object') {
    throw new TypeError(`computed candidate site ${index} must be an object`);
  }
  const requester = site.requester || entryRelative;
  if (path.isAbsolute(requester) || requester.split('/').includes('..')) {
    throw new TypeError(`computed candidate requester ${requester} is not project-relative`);
  }
  return {
    requester,
    label: site.label,
    specifiers: Array.isArray(site.specifiers) ? site.specifiers : [],
    packageClosures: Array.isArray(site.packageClosures) ? site.packageClosures : [],
  };
});
const entryIdentity = {
  root: 'project',
  components: entryRelative.split('/').map((value) => ({ encoding: 'utf8', value })),
  sourceIntegrity: packageIntegrity(await fs.readFile(entry)),
};

let authenticatedGraphSnapshot = null;
if (opts.authenticatedGraphSnapshot) {
  const snapshotText = await fs.readFile(
    path.resolve(process.cwd(), opts.authenticatedGraphSnapshot),
    'utf8',
  );
  authenticatedGraphSnapshot = JSON.parse(snapshotText);
  validateAuthenticatedGraphSnapshotV1(authenticatedGraphSnapshot);
  if (canonicalJson(authenticatedGraphSnapshot) !== snapshotText) {
    throw new TypeError('authenticated graph snapshot is not canonical JCS');
  }
}
if (targetProfile.kind === 'compiled' && !authenticatedGraphSnapshot) {
  throw new TypeError(
    'compiled policy generation requires the native authenticated graph snapshot supplied by ibex policy',
  );
}

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
const packageMetadata = new Map(); // identity -> integrity-bound package principal
const typedRequests = new Map(); // identity -> package requests/delegations (never grants)
// Exact bytes observed by Rolldown's graph analysis. The later content-tree
// snapshot must contain these same bytes and the same manifest; otherwise a
// package can race analysis A with executable tree B and inherit A's grants.
// @ref LLP 0021#decision-staging-and-principal-semantics
const analyzedPackages = new Map(); // package root -> { manifestBytes, manifest, sources }
const rootSources = new Map(); // project-relative module -> source integrity
const packageClosureOptIns = new Map(); // locator -> provenance row

// Resolve an import edge's target to its version-qualified identity by walking
// the importer's node_modules chain, exactly as the bundler's resolver does.
// Edges must carry `fromIdentity -> toIdentity` (not bare names) so a delegate
// declared by one installed version can never flow along another installed
// version's import edge. @ref LLP 0014#generator — (ENG-22818)
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
// edges (no node_modules ancestor) carry `''` on the from side. They do not
// participate in delegation, but are retained as explicit root-import
// provenance in the canonical policy so a synthetic session entry never has
// to infer its direct package surface.
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
  async load(id) {
    const pkg = packageOfModuleId(id);
    if (!pkg) return null;
    const packageRoot = packageRootForModuleId(id, pkg);
    if (!packageRoot) return null;
    let relativeModule;
    try {
      relativeModule = packageRelativeModulePath(packageRoot, id);
      const [sourceBytes, manifestBytes] = await Promise.all([
        fs.readFile(path.resolve(String(id).split('\0', 1)[0])),
        fs.readFile(path.join(packageRoot, 'package.json')),
      ]);
      let analysis = analyzedPackages.get(packageRoot);
      if (!analysis) {
        analysis = {
          manifestBytes,
          manifest: JSON.parse(manifestBytes.toString('utf8')),
          sources: new Map(),
        };
        analyzedPackages.set(packageRoot, analysis);
      } else if (!analysis.manifestBytes.equals(manifestBytes)) {
        throw new Error('package manifest changed while Rolldown loaded its modules');
      }
      const digest = packageIntegrity(sourceBytes);
      const prior = analysis.sources.get(relativeModule);
      if (prior && prior !== digest) {
        throw new Error('package module changed while Rolldown loaded its graph');
      }
      analysis.sources.set(relativeModule, digest);
      // Returning the captured bytes makes the analysis input and the recorded
      // digest one atomic value rather than two pathname reads with a race.
      return { code: sourceBytes.toString('utf8') };
    } catch (error) {
      generationErrors.push({
        message: `cannot pin package analysis input: ${error.message}`,
        file: id,
        line: 0,
      });
      return null;
    }
  },
  resolveId(specifier, importer) {
    if (!importer) return null;
    const to = packageNameOfSpecifier(specifier);
    if (!to) return null;
    recordEdge(importer, to);
    return null; // observe only; default resolution proceeds
  },
  async transform(code, id) {
    const pkg = packageOfModuleId(id);
    if (!pkg) {
      const sourcePath = String(id).split('\0', 1)[0];
      const relative = path.relative(root, sourcePath).split(path.sep).join('/');
      if (relative && !relative.startsWith('../') && !path.isAbsolute(relative)) {
        rootSources.set(relative, packageIntegrity(Buffer.from(code, 'utf8')));
      }
    }
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
      const packageRoot = packageRootForModuleId(id, pkg);
      if (!packageRoot) {
        generationErrors.push({
          message: 'package module has no stable package root',
          file: id,
          line: 0,
        });
        return null;
      }
      const analysis = analyzedPackages.get(packageRoot);
      if (!analysis) {
        generationErrors.push({
          message: 'package transform did not originate from a pinned analysis input',
          file: id,
          line: 0,
        });
        return null;
      }
      let relativeModule;
      try {
        relativeModule = packageRelativeModulePath(packageRoot, id);
      } catch (error) {
        generationErrors.push({ message: error.message, file: id, line: 0 });
        return null;
      }
      const analyzedDigest = packageIntegrity(Buffer.from(code, 'utf8'));
      const priorDigest = analysis.sources.get(relativeModule);
      if (!priorDigest || priorDigest !== analyzedDigest) {
        generationErrors.push({
          message: 'Rolldown analyzed bytes other than its pinned package source',
          file: id,
          line: 0,
        });
      }

      const identity =
        typeof analysis.manifest.version === 'string'
          ? `${analysis.manifest.name || pkg}@${analysis.manifest.version}`
          : analysis.manifest.name || pkg;
      packageIdentities.add(identity);
      if (!packageDirs.has(pkg)) packageDirs.set(pkg, new Set());
      // Normalize backslashes to agree with packageOfModuleId (ENG-22619): on
      // Windows the raw id uses `\`, so an un-normalized scan misses the marker
      // and silently drops the package's directory (hence its ibex manifest).
      packageDirs.get(pkg).add(packageRoot);

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
// Capture exact raw package bytes before any transform. The collector still
// sees modules before the shared pipeline's strip pass.
config.plugins = [graphPlugin, collector, ...config.plugins];

const bundle = await rolldown(config);
await bundle.generate({ format: 'esm', codeSplitting: false });
if (typeof bundle.close === 'function') await bundle.close();

// Candidate-only modules are ordinary graph nodes even when no literal edge
// reaches them. Analyze their frozen spellings through Rolldown's own import
// resolver, using the authored requester as referrer; the producer remains the
// sole parser and site-numbering authority.
// @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
for (const [index, declaration] of candidateDeclarations.entries()) {
  const virtualId = `\0ibex-computed-candidates:${index}`;
  const requester = path.resolve(root, declaration.requester);
  const spellings = [
    ...declaration.specifiers,
    ...declaration.packageClosures.map((locator) => bareNameOf(locator)),
  ];
  const importStatement = (specifier) => {
    if (!authenticatedGraphSnapshot) return `import ${JSON.stringify(specifier)};`;
    const matches = authenticatedGraphSnapshot.edges.filter((edge) => {
      if (edge.resolutionKind !== 'dynamic-import' || edge.specifier !== specifier) return false;
      const requester = decodeCanonicalSourceId(edge.requester);
      return requester.kind === 'file' && requester.principal.kind === 'root' &&
        requester.path.every((component) => component.encoding === 'utf8') &&
        requester.path.map((component) => component.value).join('/') === declaration.requester;
    });
    if (matches.length !== 1) {
      throw new TypeError(
        `authenticated graph has ${matches.length} dynamic candidate edges for ` +
          `${declaration.requester}#${declaration.label}:${specifier}`,
      );
    }
    return matches[0].attributes.type === 'json'
      ? `import ${JSON.stringify(specifier)} with { type: 'json' };`
      : `import ${JSON.stringify(specifier)};`;
  };
  const candidatePlugin = {
    name: `computed-candidate-analysis-${index}`,
    resolveId(specifier, importer) {
      if (specifier === virtualId) return virtualId;
      if (importer === virtualId) {
        return this.resolve(specifier, requester, { skipSelf: true });
      }
      return null;
    },
    load(id) {
      if (id !== virtualId) return null;
      return spellings.map(importStatement).join('\n');
    },
  };
  const candidateConfig = createRolldownConfig({
    input: virtualId,
    treeshake: false,
    keepRelativeCjsExternal: false,
    define: runtimeImportMetaDefine,
    compartments: false,
  });
  candidateConfig.plugins = [candidatePlugin, graphPlugin, collector, ...candidateConfig.plugins];
  const candidateBundle = await rolldown(candidateConfig);
  await candidateBundle.generate({ format: 'esm', codeSplitting: false });
  if (typeof candidateBundle.close === 'function') await candidateBundle.close();
}

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
for (const [pkg, dirs] of packageDirs) {
  for (const dir of dirs) {
    const analysis = analyzedPackages.get(dir);
    if (!analysis) {
      generationErrors.push({
        message: 'package tree has no captured Rolldown analysis inputs',
        file: path.join(dir, 'package.json'),
        line: 0,
      });
      continue;
    }
    const manifest = analysis.manifest;
    const identity =
      typeof manifest.version === 'string'
        ? `${manifest.name || pkg}@${manifest.version}`
        : manifest.name || pkg;
    let integrity;
    try {
      integrity = await authenticateAnalyzedPackageTree(dir, analysis);
    } catch (error) {
      generationErrors.push({
        message: `cannot authenticate package content: ${error.message}`,
        file: path.join(dir, 'package.json'),
        line: 0,
      });
      continue;
    }
    const metadata = {
      kind: 'package',
      name: manifest.name || pkg,
      integrity,
      locator: identity,
    };
    const priorMetadata = packageMetadata.get(identity);
    if (priorMetadata && priorMetadata.integrity !== metadata.integrity) {
      generationErrors.push({
        message: `package locator ${identity} resolves to multiple content identities`,
        file: path.join(dir, 'package.json'),
        line: 0,
      });
    }
    packageMetadata.set(identity, metadata);
    const ibex = manifest?.ibex;
    if (!ibex || typeof ibex !== 'object') continue;
    if (ibex.computedCandidateClosure === true) {
      packageClosureOptIns.set(identity, {
        package: identity,
        provenance: [{
          kind: 'direct',
          source: `${identity}/package.json#ibex.computedCandidateClosure`,
        }],
      });
    }
    typedRequests.set(identity, {
      authorities: Array.isArray(ibex.authorities) ? ibex.authorities : [],
      delegates: ibex.delegates && typeof ibex.delegates === 'object' ? ibex.delegates : {},
    });
  }
}
for (const [identity, request] of typedRequests) {
  for (const [index, authority] of request.authorities.entries()) {
    try {
      assertTypedAuthority(authority, `${identity} ibex.authorities[${index}]`);
    } catch (error) {
      generationErrors.push({ message: error.message, file: entry, line: 0 });
    }
  }
  for (const [dependency, authorities] of Object.entries(request.delegates)) {
    if (!Array.isArray(authorities)) {
      generationErrors.push({
        message: `${identity} ibex.delegates.${dependency} must be an array of typed authorities`,
        file: entry,
        line: 0,
      });
      continue;
    }
    authorities.forEach((authority, index) => {
      try {
        assertTypedAuthority(authority, `${identity} ibex.delegates.${dependency}[${index}]`);
      } catch (error) {
        generationErrors.push({ message: error.message, file: entry, line: 0 });
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Root grants (union across sites) + explicit surfaces + also-exceptions.
// ---------------------------------------------------------------------------

const rootAuthorityGrants = new Map(); // pkg -> [{ authority, provenance }]
const explicitSurfaces = new Map(); // pkg -> { endow: Set, builtins: Set }

function surfacesFor(pkg) {
  if (!explicitSurfaces.has(pkg)) {
    explicitSurfaces.set(pkg, { endow: new Set(), builtins: new Set() });
  }
  return explicitSurfaces.get(pkg);
}

rootSiteLists.sort((a, b) => compareCanonicalBytes(a.file, b.file));
for (const { file, sites } of rootSiteLists) {
  const rel = path.relative(root, file).split(path.sep).join('/');
  for (const site of sites) {
    const where = `${rel}:${site.line}`;
    if (site.capabilities.length || Object.keys(site.also).length) {
      generationErrors.push({
        message:
          'legacy grants/also strings cannot enter canonical policy; author explicit typed authorities',
        file,
        line: site.line,
      });
    }
    for (const authority of site.authorities) {
      try {
        assertTypedAuthority(authority, `${where} authorities`);
        if (!rootAuthorityGrants.has(site.package)) rootAuthorityGrants.set(site.package, []);
        rootAuthorityGrants.get(site.package).push({
          authority,
          provenance: [{ kind: 'import-site', source: where }],
        });
      } catch (error) {
        generationErrors.push({ message: error.message, file, line: site.line });
      }
    }
    for (const name of site.endow) surfacesFor(site.package).endow.add(name);
    for (const name of site.builtins) surfacesFor(site.package).builtins.add(name);
  }
}

if (generationErrors.length) {
  for (const err of generationErrors) {
    console.error(`error: ${err.message} (${path.relative(root, err.file)}:${err.line})`);
  }
  process.exit(2);
}

const sortedEdges = [...edges]
  .sort(compareCanonicalBytes)
  .map((e) => e.split('\u0000'))
  .filter(([from]) => from !== '') // root edges carry grants via import sites, not delegates
  .map(([from, to]) => [from, to]);
const rootImports = [...edges]
  .sort(compareCanonicalBytes)
  .map((edge) => edge.split('\u0000'))
  .filter(([from]) => from === '')
  .map(([, to]) => to);

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
// ---------------------------------------------------------------------------
// Artifact assembly (reproducible: sorted keys, relative paths, no timestamps).
// ---------------------------------------------------------------------------

// @ref LLP 0021#wp3--rebuild-policy-generation-and-import-site-authoring —
// canonical output contains typed selectors only. Legacy colon strings remain
// an authored-source compatibility input and cannot cross this boundary.
const typedRowsByIdentity = new Map();
for (const [bare, rows] of rootAuthorityGrants) {
  for (const identity of identitiesByName.get(bare) || []) {
    typedRowsByIdentity.set(identity, [...(typedRowsByIdentity.get(identity) || []), ...rows]);
  }
}

// Package manifests may request and attenuate authority but never originate it.
// Iterate to a fixed point so multi-hop delegation and unions across importers
// preserve the root provenance while adding one stable delegation record.
const effectiveTypedRows = resolveTypedDelegations({
  seed: typedRowsByIdentity,
  edges: sortedEdges,
  requests: typedRequests,
  bareOf: bareNameOf,
});

const importsByIdentity = new Map();
for (const [from, to] of sortedEdges) {
  if (!importsByIdentity.has(from)) importsByIdentity.set(from, new Set());
  importsByIdentity.get(from).add(to);
}

const principals = [...packageIdentities].sort(compareCanonicalBytes).map((identity) => {
  const principal = packageMetadata.get(identity);
  if (!principal) {
    throw new Error(`reachable package ${identity} has no readable integrity manifest`);
  }
  const bare = bareNameOf(identity);
  const explicit = explicitSurfaces.get(bare);
  return {
    principal,
    floor: withV1CwdObserveFloor(
      effectiveTypedRows.get(identity) || [],
    ).sort(compareCanonicalBytes),
    denials: [],
    escalationCeiling: [],
    imports: {
      builtins: [
        ...new Set([
          ...(observedBuiltins.get(identity) || []),
          ...(explicit?.builtins || []),
        ]),
      ].sort(compareCanonicalBytes),
      packages: [...(importsByIdentity.get(identity) || [])].sort(compareCanonicalBytes),
    },
    endowments: [...(explicit?.endow || [])].sort(compareCanonicalBytes),
  };
});

// Canonical policy v2 binds the reviewed authority to one graph, entry, and
// deployment profile. Candidate declarations are root-authored; package-wide
// closure rows are usable only when that exact package locator opted in.
// @ref LLP 0014#the-generated-artifact
const materializedCandidateSites = candidateDeclarations.map((site) => ({
  requester: site.requester,
  label: site.label,
  candidates: [
    ...site.specifiers,
    ...site.packageClosures.map((locator) => bareNameOf(locator)),
  ],
}));
const computedCandidates = {
  schema: 'ibex/computed-candidate-manifest/1',
  declarations: candidateDeclarations,
  packageClosureOptIns: [...packageClosureOptIns.values()],
  materializedSites: materializedCandidateSites,
};

const rootCeilingAuthorities = rootIbex.rootAuthorityCeiling || [];
if (!Array.isArray(rootCeilingAuthorities)) {
  throw new TypeError('package.json ibex.rootAuthorityCeiling must be an array');
}
const rootCeiling = rootCeilingAuthorities.map((authority, index) => {
  assertTypedAuthority(authority, `package.json ibex.rootAuthorityCeiling[${index}]`);
  return {
    authority,
    provenance: [{ kind: 'direct', source: 'package.json#ibex.rootAuthorityCeiling' }],
  };
});

rootSources.set(entryRelative, entryIdentity.sourceIntegrity);
let graphIdentity;
if (authenticatedGraphSnapshot) {
  const expectedFileNodes = new Map();
  const rootPrincipal = { kind: 'root', identity: 'project-root' };
  for (const [modulePath, sourceIntegrity] of rootSources) {
    const sourceId = encodeCanonicalSourceId({
      kind: 'file',
      principal: rootPrincipal,
      path: modulePath.split('/').map((value) => ({ encoding: 'utf8', value })),
    });
    expectedFileNodes.set(sourceId, sourceIntegrity);
  }
  for (const analysis of analyzedPackages.values()) {
    const identity = typeof analysis.manifest.version === 'string'
      ? `${analysis.manifest.name}@${analysis.manifest.version}`
      : analysis.manifest.name;
    const principal = packageMetadata.get(identity);
    if (!principal) {
      throw new TypeError(`authenticated graph package ${identity} has no policy principal`);
    }
    for (const [modulePath, sourceIntegrity] of analysis.sources) {
      const sourceId = encodeCanonicalSourceId({
        kind: 'file',
        principal,
        path: modulePath.split('/').map((value) => ({ encoding: 'utf8', value })),
      });
      expectedFileNodes.set(sourceId, sourceIntegrity);
    }
  }
  const observedFileNodes = new Map();
  for (const node of authenticatedGraphSnapshot.nodes) {
    if (decodeCanonicalSourceId(node.sourceId).kind === 'file') {
      observedFileNodes.set(node.sourceId, node.sourceIntegrity);
    }
  }
  const orderedNodeEntries = (rows) => [...rows].sort(([left], [right]) =>
    Buffer.from(left).compare(Buffer.from(right)));
  if (
    canonicalJson(orderedNodeEntries(observedFileNodes)) !==
    canonicalJson(orderedNodeEntries(expectedFileNodes))
  ) {
    throw new TypeError(
      'native authenticated graph file identities differ from the policy analysis bytes',
    );
  }
  const expectedPackages = [...packageMetadata.values()].sort(compareCanonicalBytes);
  if (canonicalJson(authenticatedGraphSnapshot.packages) !== canonicalJson(expectedPackages)) {
    throw new TypeError(
      'native authenticated graph package inventory differs from policy analysis',
    );
  }
  const entrySource = decodeCanonicalSourceId(authenticatedGraphSnapshot.entry.sourceId);
  if (
    entrySource.kind !== 'file' ||
    canonicalJson(entrySource.principal) !== canonicalJson(rootPrincipal) ||
    canonicalJson(entrySource.path) !== canonicalJson(entryIdentity.components) ||
    observedFileNodes.get(authenticatedGraphSnapshot.entry.sourceId) !==
      entryIdentity.sourceIntegrity
  ) {
    throw new TypeError(
      'native authenticated graph entry differs from the policy entry identity',
    );
  }
  const expectedCandidateSets = materializedCandidateSites.map((site) => ({
    requester: encodeCanonicalSourceId({
      kind: 'file',
      principal: rootPrincipal,
      path: site.requester.split('/').map((value) => ({ encoding: 'utf8', value })),
    }),
    label: site.label,
    candidates: [...new Set(site.candidates)].sort(compareCanonicalBytes),
  })).sort(compareCanonicalBytes);
  const observedCandidateSets = authenticatedGraphSnapshot.candidateSets.map((site) => ({
    requester: site.requester,
    label: site.label,
    candidates: site.candidates,
  })).sort(compareCanonicalBytes);
  if (canonicalJson(observedCandidateSets) !== canonicalJson(expectedCandidateSets)) {
    throw new TypeError(
      'native computed-candidate tables differ from the reviewed manifest materialization',
    );
  }
  graphIdentity = computeAuthenticatedGraphIdentityV1(authenticatedGraphSnapshot);
} else {
  const graphNodes = [
    ...[...rootSources].map(([modulePath, sourceIntegrity]) => ({
      principal: '<root>',
      modulePath,
      sourceIntegrity,
    })),
    ...[...analyzedPackages.values()].flatMap((analysis) => {
      const identity = typeof analysis.manifest.version === 'string'
        ? `${analysis.manifest.name}@${analysis.manifest.version}`
        : analysis.manifest.name;
      return [...analysis.sources].map(([modulePath, sourceIntegrity]) => ({
        principal: identity,
        modulePath,
        sourceIntegrity,
      }));
    }),
  ].sort(compareCanonicalBytes);
  const graphSnapshot = {
    graphSnapshotSchema: 'ibex/authenticated-graph-snapshot/1',
    entryIdentity,
    nodes: graphNodes,
    packages: [...packageMetadata.values()].sort(compareCanonicalBytes),
    edges: sortedEdges.map(([from, to]) => ({ from, to })),
    candidateSets: materializedCandidateSites.sort(compareCanonicalBytes),
  };
  graphIdentity = computeDomainDigest(
    'ibex/authenticated-graph-snapshot/1',
    graphSnapshot,
    [],
  );
}

const artifact = buildCanonicalPolicy(principals, rootImports, {
  graphIdentity,
  entryIdentity,
  targetProfile,
  mountProfile,
  rootCeiling,
  computedCandidates,
});
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
    const drift = classifyPolicyDrift(existingJson, artifact);
    if (drift.semanticVocabularyChange) {
      console.error('semantic vocabulary changed; review the new vocabulary before authority drift');
    }
    if (drift.expansions.length) {
      console.error('policy EXPANSIONS (review these):');
      for (const line of drift.expansions) console.error(`  + ${line}`);
    }
    if (drift.narrowings.length) {
      console.error('policy narrowing:');
      for (const line of drift.narrowings) console.error(`  - ${line}`);
    }
    if (drift.identityChanges.length) {
      console.error('policy identity changes (review graph/package content):');
      for (const line of drift.identityChanges) console.error(`  ${line}`);
    }
    if (!drift.expansions.length && !drift.narrowings.length &&
        !drift.semanticVocabularyChange && !drift.identityChanges.length) {
      console.error('(structural provenance changes only)');
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
const granted = artifact.principals.filter((p) => p.floor.length).length;
console.log(
  `wrote ${path.relative(process.cwd(), out)}: ${artifact.principals.length} package(s), ` +
    `${granted} with grants, mode=${opts.mode}`,
);
