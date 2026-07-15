import fs from 'node:fs/promises';
import path from 'node:path';

import { packageIntegrity } from './capsec-policy-authoring.mjs';

const MAX_PACKAGE_SYMLINK_DEPTH = 32;

function sameFileStamp(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function objectIdentity(stat) {
  return `${stat.dev}:${stat.ino}`;
}

function isMissingPathError(error) {
  return error?.code === 'ENOENT' || error?.code === 'ENOTDIR';
}

export async function packageTreeSnapshot(directory) {
  async function inventory() {
    const records = [];
    const digests = new Map();
    const packageRoot = path.resolve(directory);
    const rootBefore = await fs.lstat(packageRoot, { bigint: true });
    if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink()) {
      throw new Error('package root is not an authenticated ordinary directory');
    }

    function samePackageTree(candidate) {
      const relative = path.relative(packageRoot, path.resolve(candidate));
      if (
        relative === '..' ||
        relative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relative)
      ) {
        return false;
      }
      return !relative
        .split(path.sep)
        .some((component) => component === 'node_modules' || component === '.git');
    }

    function absolutePackageComponents(target) {
      if (target === packageRoot) return [];
      const prefix = packageRoot.endsWith(path.sep)
        ? packageRoot
        : `${packageRoot}${path.sep}`;
      return target.startsWith(prefix) ? target.slice(prefix.length).split(path.sep) : null;
    }

    async function readStableLink(absolute, relative, before) {
      const targetBytes = await fs.readlink(absolute, { encoding: 'buffer' });
      const after = await fs.lstat(absolute, { bigint: true });
      if (!sameFileStamp(before, after) || !after.isSymbolicLink()) {
        throw new Error(`package symlink changed while authenticating: ${relative}`);
      }
      return targetBytes;
    }

    async function resolvePackagePath(
      start,
      relative,
      inheritedState = { depth: 0, identities: new Set() },
    ) {
      const initial = path.resolve(start);
      if (!samePackageTree(initial)) return { kind: 'foreign' };

      const resolvedStack = [{ absolute: packageRoot, stat: rootBefore }];
      let pending = path.relative(packageRoot, initial).split(path.sep).filter(Boolean);
      let depth = inheritedState.depth;
      const identities = new Set(inheritedState.identities);

      while (pending.length > 0) {
        const component = pending.shift();
        if (component === '' || component === '.') continue;
        if (component === '..') {
          if (resolvedStack.length === 1) return { kind: 'foreign' };
          resolvedStack.pop();
          continue;
        }
        if (component === 'node_modules' || component === '.git') {
          return { kind: 'foreign' };
        }

        const current = resolvedStack.at(-1).absolute;
        const candidate = path.join(current, component);
        let before;
        try {
          before = await fs.lstat(candidate, { bigint: true });
        } catch (error) {
          if (isMissingPathError(error)) return { kind: 'missing' };
          throw error;
        }

        if (!before.isSymbolicLink()) {
          resolvedStack.push({ absolute: candidate, stat: before });
          continue;
        }

        const targetBytes = await readStableLink(candidate, relative, before);
        depth += 1;
        if (depth > MAX_PACKAGE_SYMLINK_DEPTH) {
          throw new Error(
            `package symlink depth exceeds ${MAX_PACKAGE_SYMLINK_DEPTH}: ${relative}`,
          );
        }
        const identity = objectIdentity(before);
        if (identities.has(identity)) {
          throw new Error(`package symlink cycle while authenticating: ${relative}`);
        }
        identities.add(identity);

        const target = targetBytes.toString('utf8');
        const targetComponents = path.isAbsolute(target)
          ? absolutePackageComponents(target)
          : target.split(path.sep);
        if (targetComponents === null) return { kind: 'foreign' };
        if (path.isAbsolute(target)) {
          resolvedStack.splice(1);
        }
        pending = [...targetComponents, ...pending];
      }

      const resolved = resolvedStack.at(-1);

      return {
        kind: 'resolved',
        absolute: resolved.absolute,
        stat: resolved.stat,
        state: { depth, identities },
      };
    }

    async function readStableFile(absolute, relative, before) {
      const bytes = await fs.readFile(absolute);
      const after = await fs.lstat(absolute, { bigint: true });
      if (!sameFileStamp(before, after) || !after.isFile()) {
        throw new Error(`package file changed while authenticating: ${relative}`);
      }
      return packageIntegrity(bytes);
    }

    // A symlink is an authenticated package object, but its target is package
    // source only when the target remains in this package's defining tree.
    // Target traversal therefore contributes analyzed-source aliases, not
    // duplicate integrity records. The native arming walk makes the broader
    // package-vs-root defining-principal decision across all bindings.
    // @ref LLP 0023#42-authenticated-package-source-is-immutable
    async function collectResolvedDigests(
      start,
      relative,
      state = { depth: 0, identities: new Set() },
      activeDirectories = new Set(),
    ) {
      const resolved = await resolvePackagePath(start, relative, state);
      if (resolved.kind !== 'resolved') return;

      const before = resolved.stat;
      if (before.isFile()) {
        digests.set(relative, await readStableFile(resolved.absolute, relative, before));
        return;
      }
      if (!before.isDirectory()) {
        throw new Error(`package content contains an unsupported file type: ${relative}`);
      }

      const directoryIdentity = objectIdentity(before);
      if (activeDirectories.has(directoryIdentity)) {
        throw new Error(`package symlink cycle while authenticating: ${relative}`);
      }
      const nextActiveDirectories = new Set(activeDirectories);
      nextActiveDirectories.add(directoryIdentity);

      const entries = await fs.readdir(resolved.absolute, { withFileTypes: true });
      entries.sort((a, b) => Buffer.from(a.name).compare(Buffer.from(b.name)));
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        const childAbsolute = path.join(resolved.absolute, entry.name);
        const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
        await collectResolvedDigests(
          childAbsolute,
          childRelative,
          resolved.state,
          nextActiveDirectories,
        );
      }

      const after = await fs.lstat(resolved.absolute, { bigint: true });
      if (!sameFileStamp(before, after) || !after.isDirectory()) {
        throw new Error(`package directory changed while authenticating: ${relative}`);
      }
    }

    async function walk(current, relative) {
      const entries = await fs.readdir(current, { withFileTypes: true });
      entries.sort((a, b) => Buffer.from(a.name).compare(Buffer.from(b.name)));
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        const absolute = path.join(current, entry.name);
        const rel = relative ? `${relative}/${entry.name}` : entry.name;
        const before = await fs.lstat(absolute, { bigint: true });
        if (before.isSymbolicLink()) {
          const targetBytes = await readStableLink(absolute, rel, before);
          records.push([rel, `symlink-${packageIntegrity(targetBytes)}`]);
          await collectResolvedDigests(absolute, rel);
          const after = await fs.lstat(absolute, { bigint: true });
          if (!sameFileStamp(before, after) || !after.isSymbolicLink()) {
            throw new Error(`package symlink changed while authenticating: ${rel}`);
          }
        }
        if (before.isDirectory()) {
          await walk(absolute, rel);
          const after = await fs.lstat(absolute, { bigint: true });
          if (!sameFileStamp(before, after)) {
            throw new Error(`package directory changed while authenticating: ${rel}`);
          }
        } else if (before.isFile()) {
          const digest = await readStableFile(absolute, rel, before);
          records.push([rel, digest]);
          digests.set(rel, digest);
        } else if (!before.isSymbolicLink()) {
          throw new Error(`package content contains an unsupported file type: ${rel}`);
        }
      }
    }

    await walk(packageRoot, '');
    const rootAfter = await fs.lstat(packageRoot, { bigint: true });
    if (!sameFileStamp(rootBefore, rootAfter)) {
      throw new Error('package root changed while authenticating its inventory');
    }
    records.sort((a, b) => Buffer.from(a[0]).compare(Buffer.from(b[0])));
    return { records, digests };
  }

  const first = await inventory();
  const second = await inventory();
  if (JSON.stringify(first.records) !== JSON.stringify(second.records)) {
    throw new Error('package content changed between authenticated inventory passes');
  }
  return {
    integrity: packageIntegrity(JSON.stringify(second.records)),
    digests: second.digests,
  };
}

export async function authenticateAnalyzedPackageTree(directory, analysis) {
  const snapshot = await packageTreeSnapshot(directory);
  const manifestDigest = snapshot.digests.get('package.json');
  if (manifestDigest !== packageIntegrity(analysis.manifestBytes)) {
    throw new Error('package.json differs from the manifest used during graph analysis');
  }
  for (const [relativeModule, analyzedDigest] of analysis.sources) {
    if (snapshot.digests.get(relativeModule) !== analyzedDigest) {
      throw new Error(`${relativeModule} differs from the bytes used during graph analysis`);
    }
  }
  return snapshot.integrity;
}

export function packageRootForModuleId(id, pkg) {
  const normalized = String(id).replace(/\\/g, '/');
  const marker = 'node_modules/';
  const index = normalized.lastIndexOf(marker);
  return index === -1
    ? null
    : normalized.slice(0, index + marker.length) + pkg;
}

export function packageRelativeModulePath(root, id) {
  const absolute = path.resolve(String(id).split('\0', 1)[0]);
  const relative = path.relative(path.resolve(root), absolute);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error(`analyzed package module escapes its package root: ${id}`);
  }
  return relative.split(path.sep).join('/');
}
