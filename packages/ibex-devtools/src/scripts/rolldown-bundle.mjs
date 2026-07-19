#!/usr/bin/env node
import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';
import {
  createRolldownConfig,
  runtimeImportMetaDefine,
  packageOfModuleId,
  packageIdentityOfModuleId,
} from './transforms.mjs';

// @ref LLP 0013#mechanism-3 — encode a package name into a chunk name reversibly
// (filesystem-safe), so the runtime loader can recover the package a chunk
// belongs to and stamp its Domain principal. Only `/` needs escaping for scopes.
const PKG_CHUNK_PREFIX = '__ibexpkg__';
function encodePackageChunkName(pkg) {
  return PKG_CHUNK_PREFIX + String(pkg).replace(/\//g, '__SLASH__');
}

let rolldown;
try {
  ({ rolldown } = await import('rolldown'));
} catch (err) {
  console.error('Failed to load rolldown. Run `bun install` at the repo root to install JS dependencies.');
  console.error(err?.message || err);
  process.exit(1);
}

const args = process.argv.slice(2);
const opts = {};
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--entry') {
    opts.entry = args[++i];
  } else if (arg === '--out') {
    opts.out = args[++i];
  } else if (arg === '--sourcemap') {
    opts.sourcemap = true;
  } else if (arg === '--format') {
    opts.format = args[++i];
  } else if (arg === '--name') {
    opts.name = args[++i];
  } else if (arg === '--lower-classes') {
    opts.lowerClasses = true;
  } else if (arg === '--compartments') {
    // @ref LLP 0013#mechanism-2 — per-package free-global rewrite.
    opts.compartments = true;
  } else if (arg === '--per-package-chunks') {
    // @ref LLP 0013#mechanism-3 — emit one chunk per npm package so each
    // compiles into its own Domain at load time, giving bundled apps
    // per-package frame attribution (not just the unbundled path).
    opts.perPackageChunks = true;
  } else if (arg === '--cache-manifest') {
    // Runtime generated-code cache: bind graph inputs and outputs by digest.
    // Build-time vendoring does not need or commit this sidecar.
    opts.cacheManifest = true;
  } else if (arg === '--source-provenance-authority') {
    // Native-only, digest-checked binding input. The file may contain backing
    // paths; the emitted provenance projection never does.
    opts.sourceProvenanceAuthority = args[++i];
  } else if (arg === '--source-provenance-authority-sha256') {
    opts.sourceProvenanceAuthoritySha256 = args[++i];
  }
}

if (!opts.entry || !opts.out) {
  console.error('Usage: rolldown-bundle.mjs --entry <file> --out <file> [--sourcemap]');
  process.exit(2);
}

const entry = path.resolve(process.cwd(), opts.entry);
const out = path.resolve(process.cwd(), opts.out);
const utf8Compare = (left, right) =>
  Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
const canonicalJson = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
};
const digestFile = async (file) =>
  createHash('sha256').update(await fs.readFile(file)).digest('hex');
const digestJson = (value) =>
  createHash('sha256').update(canonicalJson(value)).digest('hex');
const isSha256Hex = (value) =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const isDigestIdentity = (value) =>
  typeof value === 'string' && /^sha256-[A-Za-z0-9_-]{43}$/.test(value);
const isPrincipal = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.kind === 'root') {
    return typeof value.identity === 'string' && value.identity.length > 0;
  }
  return value.kind === 'package' &&
    typeof value.name === 'string' && value.name.length > 0 &&
    typeof value.locator === 'string' && value.locator.length > 0 &&
    isDigestIdentity(value.integrity);
};
const pathIsWithin = (root, candidate) => {
  const relative = path.relative(root, candidate);
  return relative === '' ||
    (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
};
const sourceLabelForVirtualPath = (virtualPath) => {
  let label = 'file://';
  for (const byte of Buffer.from(virtualPath, 'utf8')) {
    if (byte === 0x2f ||
        (byte >= 0x30 && byte <= 0x39) ||
        (byte >= 0x41 && byte <= 0x5a) ||
        (byte >= 0x61 && byte <= 0x7a) ||
        byte === 0x2d || byte === 0x2e || byte === 0x5f || byte === 0x7e) {
      label += String.fromCharCode(byte);
    } else {
      label += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return label;
};
const sourceIdFor = (definingPrincipal, logicalRoot, lexicalComponents) => {
  const identity = {
    definingPrincipal,
    kind: 'file',
    lexicalComponents,
    logicalRoot,
    sourceIdSchema: 'ibex.source-id.v1',
  };
  return `ibex-source-id-v1:${Buffer.from(canonicalJson(identity), 'utf8')
    .toString('base64url')}`;
};

// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
// The bundler is not allowed to infer a defining principal from node_modules
// text. Native supplies the exact armed root/package bindings and an expected
// digest. Backing spellings are consumed only while constructing the portable
// projection; no backing path is copied into `sourceProvenance`.
const loadSourceProvenanceAuthority = async () => {
  const authorityPath = opts.sourceProvenanceAuthority;
  const expectedDigest = opts.sourceProvenanceAuthoritySha256;
  if (!authorityPath && !expectedDigest) return null;
  if (!authorityPath || !isSha256Hex(expectedDigest)) {
    throw new Error('source provenance authority requires a path and lowercase SHA-256 digest');
  }
  if (!opts.cacheManifest) {
    throw new Error('source provenance authority requires --cache-manifest');
  }
  const bytes = await fs.readFile(authorityPath);
  const observedDigest = createHash('sha256').update(bytes).digest('hex');
  if (observedDigest !== expectedDigest) {
    throw new Error('source provenance authority digest mismatch');
  }
  let authority;
  try {
    authority = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('source provenance authority is not valid UTF-8 JSON');
  }
  const allowedKeys = [
    'schema', 'armedSnapshotDigest', 'packageGraphDigest', 'rootIdentity', 'bindings',
  ];
  if (!authority || typeof authority !== 'object' || Array.isArray(authority) ||
      Object.keys(authority).some((key) => !allowedKeys.includes(key)) ||
      authority.schema !== 'ibex/source-provenance-authority/1' ||
      !isDigestIdentity(authority.armedSnapshotDigest) ||
      !isDigestIdentity(authority.packageGraphDigest) ||
      !isPrincipal(authority.rootIdentity) || authority.rootIdentity.kind !== 'root' ||
      !Array.isArray(authority.bindings) || authority.bindings.length === 0) {
    throw new Error('source provenance authority has an invalid closed shape');
  }

  const bindings = [];
  for (const raw of authority.bindings) {
    const bindingKeys = ['logicalRoot', 'owner', 'backingRoot'];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
        Object.keys(raw).some((key) => !bindingKeys.includes(key)) ||
        (raw.logicalRoot !== 'project' && raw.logicalRoot !== 'package') ||
        typeof raw.backingRoot !== 'string' || !path.isAbsolute(raw.backingRoot)) {
      throw new Error('source provenance authority contains an invalid binding');
    }
    const owner = raw.logicalRoot === 'project' ? authority.rootIdentity : raw.owner;
    if (!isPrincipal(owner) ||
        (raw.logicalRoot === 'project' && (raw.owner !== undefined || owner.kind !== 'root')) ||
        (raw.logicalRoot === 'package' && owner.kind !== 'package')) {
      throw new Error('source provenance binding owner does not match its logical root');
    }
    const backingRoot = await fs.realpath(raw.backingRoot);
    bindings.push({ logicalRoot: raw.logicalRoot, owner, backingRoot });
  }
  const projectBindings = bindings.filter((binding) => binding.logicalRoot === 'project');
  if (projectBindings.length !== 1) {
    throw new Error('source provenance authority requires exactly one project binding');
  }
  const projectRoot = projectBindings[0].backingRoot;
  const seenRoots = new Set();
  for (const binding of bindings) {
    if (!pathIsWithin(projectRoot, binding.backingRoot)) {
      throw new Error('source provenance package binding escapes the project binding');
    }
    if (seenRoots.has(binding.backingRoot)) {
      throw new Error('source provenance bindings have an ambiguous canonical root');
    }
    seenRoots.add(binding.backingRoot);
    const relative = path.relative(projectRoot, binding.backingRoot);
    const components = relative === '' ? [] : relative.split(path.sep);
    binding.virtualPrefix = components.length === 0
      ? '/project'
      : `/project/${components.join('/')}`;
  }
  bindings.sort((left, right) =>
    right.backingRoot.length - left.backingRoot.length ||
    utf8Compare(left.backingRoot, right.backingRoot));
  return {
    authorityDigest: observedDigest,
    armedSnapshotDigest: authority.armedSnapshotDigest,
    packageGraphDigest: authority.packageGraphDigest,
    projectRoot,
    bindings,
  };
};
const sourceProvenanceAuthority = await loadSourceProvenanceAuthority();
const missingDigest = createHash('sha256').update('missing').digest('hex');
const metadataNames = [
  'package.json', 'bun.lock', 'bun.lockb', 'package-lock.json',
  'pnpm-lock.yaml', 'yarn.lock', 'tsconfig.json', 'jsconfig.json',
];
const directoryDigest = async (directory) => {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const rows = [];
  for (const item of entries) {
    const kind = item.isSymbolicLink() ? 'l' : item.isDirectory() ? 'd' : item.isFile() ? 'f' : 'o';
    let target = '';
    if (kind === 'l') target = await fs.readlink(path.join(directory, item.name));
    rows.push({ name: item.name, row: `${kind}\0${item.name}\0${target}\n` });
  }
  rows.sort((a, b) => utf8Compare(a.name, b.name));
  return createHash('sha256').update(rows.map((item) => item.row).join('')).digest('hex');
};

const resolutionInputMap = new Map();
const resolutionInputTasks = new Map();
const rememberResolutionInput = (record) => {
  // First observation wins: later hooks run after a resolver decision and
  // must never bless a mutation that changed that decision's precedence.
  if (!resolutionInputMap.has(record.path)) resolutionInputMap.set(record.path, record);
};
const snapshotPathState = async (candidate) => {
  const absolute = path.resolve(candidate);
  // Rolldown may resolve thousands of imports from the same directory. The
  // first pre-resolution observation is the security witness; recomputing its
  // full directory/file digest for every import is both redundant and O(graph
  // size × directory size). Reserve the path before awaiting so concurrent
  // resolve hooks cannot duplicate that work or replace the first witness.
  if (resolutionInputMap.has(absolute)) return;
  const inFlight = resolutionInputTasks.get(absolute);
  if (inFlight) return inFlight;
  const capture = (async () => {
    let record;
    try {
      const stat = await fs.lstat(absolute);
      if (stat.isSymbolicLink()) {
        record = {
          kind: 'symlink',
          path: absolute,
          sha256: createHash('sha256').update(await fs.readlink(absolute)).digest('hex'),
        };
      } else if (stat.isDirectory()) {
        record = { kind: 'directory', path: absolute, sha256: await directoryDigest(absolute) };
      } else if (stat.isFile()) {
        record = { kind: 'file', path: absolute, sha256: await digestFile(absolute) };
      } else {
        record = { kind: 'missing', path: absolute, sha256: missingDigest };
      }
    } catch {
      record = { kind: 'missing', path: absolute, sha256: missingDigest };
    }
    resolutionInputMap.set(absolute, record);
  })();
  resolutionInputTasks.set(absolute, capture);
  try {
    await capture;
  } finally {
    resolutionInputTasks.delete(absolute);
  }
};
const checkedSymlinkComponents = new Set();
const symlinkComponentTasks = new Map();
const addSymlinkComponents = async (file) => {
  const absolute = path.resolve(file);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const component of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    if (checkedSymlinkComponents.has(current)) continue;
    const existing = symlinkComponentTasks.get(current);
    if (existing) {
      await existing;
      continue;
    }
    const componentPath = current;
    const capture = (async () => {
      try {
        const stat = await fs.lstat(componentPath);
        if (stat.isSymbolicLink()) {
          rememberResolutionInput({
            kind: 'symlink',
            path: componentPath,
            sha256: createHash('sha256').update(await fs.readlink(componentPath)).digest('hex'),
          });
        }
        return true;
      } catch {
        return false;
      }
    })();
    symlinkComponentTasks.set(componentPath, capture);
    const exists = await capture;
    symlinkComponentTasks.delete(componentPath);
    checkedSymlinkComponents.add(componentPath);
    if (!exists) break;
  }
};
const extensionCandidates = ['', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json'];
const snapshotFileResolutionCandidates = async (candidate) => {
  await snapshotPathState(path.dirname(candidate));
  for (const extension of extensionCandidates) {
    await snapshotPathState(candidate + extension);
    if (extension) await snapshotPathState(path.join(candidate, 'index' + extension));
  }
  await addSymlinkComponents(candidate);
};
const snapshotResolutionRequest = async (source, importer) => {
  if (typeof source !== 'string' || source.startsWith('\0')) return;
  const importerPath = importer && !importer.startsWith('\0') ? importer : entry;
  const base = path.dirname(importerPath);
  await addSymlinkComponents(importerPath);

  // Resolver configuration can live above a nested VCS/project boundary (for
  // example a workspace package with a hoisted package.json/tsconfig). Record
  // each exact metadata candidate through the filesystem root. Do not hash
  // whole ancestor directories: unrelated files in $HOME or / must not churn
  // an otherwise valid bundle cache.
  for (let current = base, depth = 0; depth < 64; depth++) {
    for (const name of metadataNames) await snapshotPathState(path.join(current, name));
    if (path.dirname(current) === current) break;
    current = path.dirname(current);
  }

  if (source.startsWith('.') || path.isAbsolute(source)) {
    const candidate = path.isAbsolute(source) ? source : path.resolve(base, source);
    await snapshotFileResolutionCandidates(candidate);
    return;
  }

  const parts = source.split('/');
  const packageName = source.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  const packageSubpathParts = source.startsWith('@') ? parts.slice(2) : parts.slice(1);
  // Node package lookup does not stop at `.git` or the nearest package
  // metadata boundary. Witness every ancestor node_modules candidate so a
  // newly-created, closer hoisted package cannot make an old bundle resolve to
  // different code while all of its previous positive dependencies remain.
  for (let current = base, depth = 0; depth < 64; depth++) {
    const nodeModules = path.join(current, 'node_modules');
    const packageRoot = path.join(nodeModules, packageName);
    await snapshotPathState(nodeModules);
    await snapshotPathState(packageRoot);
    await snapshotPathState(path.join(packageRoot, 'package.json'));
    if (packageSubpathParts.length > 0) {
      const subpath = path.resolve(packageRoot, ...packageSubpathParts);
      // Reject pkg/../outside-style escape spellings rather than using an
      // import string to make the witness collector scan unrelated paths.
      if (subpath === packageRoot || subpath.startsWith(packageRoot + path.sep)) {
        await snapshotFileResolutionCandidates(subpath);
      }
    } else {
      // package.json main/exports is itself digest-bound above; witness the
      // legacy/default index extension precedence as well.
      await snapshotFileResolutionCandidates(path.join(packageRoot, 'index'));
    }
    if (path.dirname(current) === current) break;
    current = path.dirname(current);
  }
};

const digestResolutionInput = async (record) => {
  try {
    const stat = await fs.lstat(record.path);
    if (record.kind === 'missing') return null;
    if (record.kind === 'symlink' && stat.isSymbolicLink()) {
      return createHash('sha256').update(await fs.readlink(record.path)).digest('hex');
    }
    if (record.kind === 'directory' && stat.isDirectory()) return directoryDigest(record.path);
    if (record.kind === 'file' && stat.isFile()) return digestFile(record.path);
    return null;
  } catch {
    return record.kind === 'missing' ? missingDigest : null;
  }
};

// Capture the exact pre-transform source text Rolldown hands to its plugin
// pipeline. The cache manifest is built from these bytes, not a post-build
// reread that could authenticate old output against a concurrently edited file.
const capturedModules = new Map();
let captureBarrierUsed = false;
const sourceCapturePlugin = {
  name: 'ibex-cache-source-capture',
  async resolveId(source, importer) {
    if (opts.cacheManifest) await snapshotResolutionRequest(source, importer);
    // Resolve through the remaining plugin/default resolver exactly once and
    // return that decision. Capturing the selected module's parent directory
    // closes package.json main/exports remapping holes that cannot be inferred
    // from the bare specifier (for example pkg -> ./lib/entry). A new
    // higher-precedence sibling then changes this first-observed witness even
    // though the selected file and package.json bytes are unchanged.
    const resolved = await this.resolve(source, importer, { skipSelf: true });
    const resolvedId = typeof resolved === 'string' ? resolved : resolved?.id;
    if (opts.cacheManifest && resolved && !resolved.external &&
        typeof resolvedId === 'string' && !resolvedId.startsWith('\0') &&
        path.isAbsolute(resolvedId)) {
      await snapshotPathState(path.dirname(resolvedId));
      await snapshotPathState(resolvedId);
      await addSymlinkComponents(resolvedId);
    }
    return resolved;
  },
  async transform(code, id) {
    if (!id.startsWith('\0') && path.isAbsolute(id)) {
      const real = await fs.realpath(id);
      capturedModules.set(real, {
        id,
        code,
        sha256: createHash('sha256').update(code).digest('hex'),
      });
      const barrierEntry = process.env.IBEX_TEST_BUNDLE_BARRIER_ENTRY;
      const barrierDir = process.env.IBEX_TEST_BUNDLE_BARRIER_DIR;
      if (!captureBarrierUsed && barrierEntry && barrierDir &&
          real === await fs.realpath(barrierEntry)) {
        captureBarrierUsed = true;
        await fs.mkdir(barrierDir, { recursive: true });
        await fs.writeFile(path.join(barrierDir, 'captured'), '');
        const deadline = Date.now() + 10000;
        while (!(await (async () => {
          try { await fs.stat(path.join(barrierDir, 'release')); return true; }
          catch { return false; }
        })())) {
          if (Date.now() >= deadline) throw new Error('bundle capture test barrier timed out');
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
      }
    }
    return null;
  },
};
if (opts.cacheManifest) await snapshotResolutionRequest(entry, undefined);
const rolldownConfig = createRolldownConfig({
  input: entry,
  // Disable tree-shaking so that calls with observable side effects
  // (e.g. URL.canParse() throwing on missing args, assert.throws callbacks)
  // are not silently removed during bundling.
  treeshake: false,
  // Keep relative .cjs files external so they go through runtime require().
  // This preserves require.cache, require.resolve, __dirname/__filename semantics.
  keepRelativeCjsExternal: true,
  define: runtimeImportMetaDefine,
  compartments: opts.compartments || false,
});
rolldownConfig.plugins.unshift(sourceCapturePlugin);
const bundle = await rolldown(rolldownConfig);

// @ref LLP 0013#mechanism-3 — per-package chunking. Group each npm package's
// modules into a chunk named after the package; the entry chunk requires them,
// and the runtime loader compiles each chunk into its own Domain stamped with
// the package principal. Off by default (one flat chunk); iife can't split.
const perPackageChunks = opts.perPackageChunks && (opts.format || 'cjs') !== 'iife';
const outDir = path.dirname(out);
const outBase = path.basename(out);
const writeResult = await bundle.write({
  format: opts.format || 'cjs',
  ...(opts.format === 'iife' ? { name: opts.name || 'ExactRuntimeBundle' } : {}),
  sourcemap: opts.sourcemap ? true : false,
  exports: 'auto',
  ...(perPackageChunks
    ? {
        // Multi-chunk output must use `dir` (+ names), not `file`.
        dir: outDir,
        entryFileNames: outBase,
        chunkFileNames: '[name].js',
        advancedChunks: {
          groups: [
            {
              name: (id) => {
                // Group by the version-qualified identity (`name@version`) so two
                // installed versions of one package become separate chunks (hence
                // separate Domains/principals), matching the runtime loader's
                // identity. @ref LLP 0013#resolved-questions — (ENG-22621)
                const pkg = packageIdentityOfModuleId(id);
                return pkg ? encodePackageChunkName(pkg) : null;
              },
              // Detect package modules via packageOfModuleId, which normalizes
              // path separators — a POSIX-only `/node_modules/` regex would miss
              // Windows ids using backslashes (`C:\app\node_modules\evil\...`),
              // silently leaving those packages in the root bundle and disabling
              // per-package attribution on Windows. (ENG-22698)
              test: (id) => packageOfModuleId(id) !== null,
            },
          ],
        },
      }
    : { file: out, codeSplitting: false }),
});

if (typeof bundle.close === 'function') {
  await bundle.close();
}

// Emit a content-addressed dependency/output manifest next to the output.
// Cache identity never trusts mtime or length: both every source in the graph
// and every published output are SHA-256 bound. Real file paths only — virtual
// modules (\0-prefixed) and externals are skipped.
if (opts.cacheManifest) {
  const moduleIds = new Set([await fs.realpath(entry)]);
  const moduleOutputs = new Map();
  for (const item of writeResult?.output ?? []) {
    if (item?.type === 'chunk' && item.modules) {
      for (const id of Object.keys(item.modules)) {
        if (!id.startsWith('\0') && path.isAbsolute(id)) {
          const modulePath = await fs.realpath(id);
          moduleIds.add(modulePath);
          if (!moduleOutputs.has(modulePath)) moduleOutputs.set(modulePath, new Set());
          moduleOutputs.get(modulePath).add(item.fileName);
        }
      }
    }
  }
  const deps = [];
  for (const modulePath of [...moduleIds].sort(utf8Compare)) {
    const captured = capturedModules.get(modulePath);
    if (!captured) {
      throw new Error(`cache source capture missed ${modulePath}`);
    }
    const currentCode = await fs.readFile(modulePath, 'utf8');
    const currentDigest = createHash('sha256').update(currentCode).digest('hex');
    if (currentDigest !== captured.sha256) {
      throw new Error(`source changed while bundling: ${modulePath}`);
    }
    deps.push({ path: modulePath, sha256: captured.sha256 });
  }

  for (const record of resolutionInputMap.values()) {
    const currentDigest = await digestResolutionInput(record);
    if (currentDigest !== record.sha256) {
      throw new Error(`module resolution input changed while bundling: ${record.path}`);
    }
  }
  const resolutionInputs = [...resolutionInputMap.values()].sort((a, b) => {
    const byPath = utf8Compare(a.path, b.path);
    return byPath || utf8Compare(a.kind, b.kind);
  });
  const resolutionDigest = createHash('sha256')
    .update(JSON.stringify(resolutionInputs))
    .digest('hex');
  const outputs = [];
  const outputNames = new Set([path.basename(out)]);
  for (const item of writeResult?.output ?? []) {
    if (typeof item?.fileName === 'string') outputNames.add(item.fileName);
  }
  for (const outputName of outputNames) {
    const outputPath = path.join(outDir, outputName);
    outputs.push({ path: outputName, sha256: await digestFile(outputPath) });
  }
  outputs.sort((a, b) => utf8Compare(a.path, b.path));
  let sourceProvenance = null;
  if (sourceProvenanceAuthority) {
    const depIndexByPath = new Map(deps.map((dep, index) => [dep.path, index]));
    const modules = [];
    for (const modulePath of [...moduleIds].sort(utf8Compare)) {
      if (!pathIsWithin(sourceProvenanceAuthority.projectRoot, modulePath)) {
        throw new Error(`source provenance module escapes the project binding: ${modulePath}`);
      }
      const binding = sourceProvenanceAuthority.bindings.find((candidate) =>
        pathIsWithin(candidate.backingRoot, modulePath));
      if (!binding) {
        throw new Error(`source provenance module has no authenticated binding: ${modulePath}`);
      }
      const bindingRelative = path.relative(binding.backingRoot, modulePath);
      const lexicalComponents = bindingRelative === '' ? [] : bindingRelative.split(path.sep);
      if (lexicalComponents.length === 0 ||
          lexicalComponents.some((component) => !component || component === '.' || component === '..')) {
        throw new Error(`source provenance module has an invalid binding-relative path: ${modulePath}`);
      }
      const projectRelative = path.relative(sourceProvenanceAuthority.projectRoot, modulePath);
      const projectComponents = projectRelative.split(path.sep);
      const virtualPath = `/project/${projectComponents.join('/')}`;
      const chunks = [...(moduleOutputs.get(modulePath) ?? [])].sort(utf8Compare);
      if (chunks.length === 0) {
        throw new Error(`source provenance module has no emitted chunk: ${modulePath}`);
      }
      const depIndex = depIndexByPath.get(modulePath);
      if (depIndex === undefined) {
        throw new Error(`source provenance module has no authenticated dependency row: ${modulePath}`);
      }
      modules.push({
        sourceId: sourceIdFor(binding.owner, binding.logicalRoot, lexicalComponents),
        sourceLabel: sourceLabelForVirtualPath(virtualPath),
        virtualPath,
        bindingVirtualPrefix: binding.virtualPrefix,
        sourceIdentity: {
          definingPrincipal: binding.owner,
          logicalRoot: binding.logicalRoot,
          lexicalComponents,
        },
        sourceSha256: deps[depIndex].sha256,
        depIndex,
        chunks,
      });
    }
    modules.sort((left, right) => utf8Compare(left.sourceId, right.sourceId));
    for (let index = 1; index < modules.length; index++) {
      if (modules[index - 1].sourceId === modules[index].sourceId) {
        throw new Error('two original modules produced the same authenticated SourceId');
      }
    }
    const projection = {
      schema: 'ibex/source-provenance/1',
      armedSnapshotDigest: sourceProvenanceAuthority.armedSnapshotDigest,
      packageGraphDigest: sourceProvenanceAuthority.packageGraphDigest,
      authorityDigest: sourceProvenanceAuthority.authorityDigest,
      modules,
    };
    sourceProvenance = { ...projection, digest: digestJson(projection) };

    // Rolldown's map normally names backing files. Rewrite every real original
    // to the same virtual SourceLabel used by raw execution before hashing the
    // generated outputs. A map source that looks like a real file but cannot be
    // joined to the authenticated graph is refused rather than leaked.
    const sourceLabelByBackingPath = new Map(sourceProvenance.modules.map((module) => [
      deps[module.depIndex].path,
      module.sourceLabel,
    ]));
    for (const outputName of outputNames) {
      if (!outputName.endsWith('.map')) continue;
      const mapPath = path.join(outDir, outputName);
      const sourceMap = JSON.parse(await fs.readFile(mapPath, 'utf8'));
      if (!Array.isArray(sourceMap.sources)) {
        throw new Error(`generated source map has no sources array: ${outputName}`);
      }
      const mapDirectory = path.dirname(mapPath);
      const sourceRoot = typeof sourceMap.sourceRoot === 'string' ? sourceMap.sourceRoot : '';
      sourceMap.sources = await Promise.all(sourceMap.sources.map(async (rawSource) => {
        if (typeof rawSource !== 'string' || rawSource.includes('\0')) {
          throw new Error(`generated source map has an invalid source: ${outputName}`);
        }
        if (/^(?:ibex|node|rolldown):/.test(rawSource)) return rawSource;
        const candidates = [];
        if (rawSource.startsWith('file://')) {
          try {
            candidates.push(decodeURIComponent(new URL(rawSource).pathname));
          } catch {
            throw new Error(`generated source map has an invalid file URL: ${outputName}`);
          }
        } else if (path.isAbsolute(rawSource)) {
          candidates.push(rawSource);
        } else {
          candidates.push(path.resolve(mapDirectory, sourceRoot, rawSource));
          candidates.push(path.resolve(process.cwd(), sourceRoot, rawSource));
        }
        for (const candidate of candidates) {
          let canonicalCandidate;
          try {
            canonicalCandidate = await fs.realpath(candidate);
          } catch {
            continue;
          }
          const label = sourceLabelByBackingPath.get(canonicalCandidate);
          if (label) return label;
        }
        throw new Error(`source map source is outside the authenticated module graph: ${rawSource}`);
      }));
      delete sourceMap.sourceRoot;
      await fs.writeFile(mapPath, JSON.stringify(sourceMap));
    }
    // Source-map rewriting changes an output; refresh every output digest so
    // the v4 graph key below commits the exact published bytes.
    for (const output of outputs) {
      output.sha256 = await digestFile(path.join(outDir, output.path));
    }
  }
  // v4 binds the portable, per-original provenance projection and every
  // generated output digest into the graph key. The cache-private dependency
  // rows still carry backing paths for
  // freshness checks; the runtime-visible `sourceProvenance` projection does
  // not. @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
  const graphDigest = sourceProvenance
    ? digestJson({ deps, outputs, sourceProvenanceDigest: sourceProvenance.digest })
    : createHash('sha256').update(JSON.stringify(deps)).digest('hex');
  const manifestPath = `${out}.deps.json`;
  const manifestTmp = `${manifestPath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(
    manifestTmp,
    JSON.stringify({
      version: sourceProvenance ? 4 : 3,
      entry: await fs.realpath(entry),
      resolutionDigest,
      graphDigest,
      deps,
      resolutionInputs,
      outputs,
      ...(sourceProvenance ? { sourceProvenance } : {}),
    })
  );
  await fs.rename(manifestTmp, manifestPath);
}

if (opts.lowerClasses) {
  let babel;
  try {
    babel = await import('@babel/core');
  } catch (err) {
    console.error('Failed to load @babel/core for --lower-classes. Run `bun install` at the repo root.');
    console.error(err?.message || err);
    process.exit(1);
  }

  const code = await fs.readFile(out, 'utf8');
  let inputSourceMap;
  const mapPath = `${out}.map`;
  if (opts.sourcemap) {
    try {
      inputSourceMap = JSON.parse(await fs.readFile(mapPath, 'utf8'));
    } catch {
      inputSourceMap = undefined;
    }
  }

  const containLoweredIifeHelpers = ({ types }) => ({
    name: 'ibex-contain-lowered-iife-helpers',
    visitor: {
      Program: {
        exit(programPath) {
          // Babel's class transform emits helper declarations at Program
          // scope, outside Rolldown's own IIFE. Hermes evaluates this bundle
          // as a script, so those helpers would otherwise become realm-global
          // properties. Put the final transformed Program in one more closure;
          // the runtime's intentional exports already use globalThis.
          // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
          const body = types.blockStatement(programPath.node.body);
          body.directives = programPath.node.directives;
          programPath.node.directives = [];
          const closure = types.functionExpression(null, [], body);
          const call = types.callExpression(
            types.memberExpression(closure, types.identifier('call')),
            [types.identifier('globalThis')],
          );
          programPath.node.body = [types.expressionStatement(call)];
        },
      },
    },
  });

  const result = await babel.transformAsync(code, {
    babelrc: false,
    configFile: false,
    filename: out,
    inputSourceMap,
    sourceMaps: opts.sourcemap ? true : false,
    plugins: [
      ['@babel/plugin-transform-classes', { loose: true }],
      ...(opts.format === 'iife' ? [containLoweredIifeHelpers] : []),
    ],
  });

  if (!result?.code) {
    console.error('Babel --lower-classes transform produced no output.');
    process.exit(1);
  }

  await fs.writeFile(out, result.code);
  if (opts.sourcemap && result.map) {
    await fs.writeFile(mapPath, JSON.stringify(result.map));
  }
}
