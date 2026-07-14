import fs from 'node:fs/promises';
import path from 'node:path';

import { packageIntegrity } from './capsec-policy-authoring.mjs';

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

export async function packageTreeSnapshot(directory) {
  async function inventory() {
    const records = [];
    const digests = new Map();
    const rootBefore = await fs.lstat(directory, { bigint: true });
    if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink()) {
      throw new Error('package root is not an authenticated ordinary directory');
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
          throw new Error(`package content contains an unauthenticated symlink: ${rel}`);
        }
        if (before.isDirectory()) {
          await walk(absolute, rel);
          const after = await fs.lstat(absolute, { bigint: true });
          if (!sameFileStamp(before, after)) {
            throw new Error(`package directory changed while authenticating: ${rel}`);
          }
        } else if (before.isFile()) {
          const bytes = await fs.readFile(absolute);
          const after = await fs.lstat(absolute, { bigint: true });
          if (!sameFileStamp(before, after)) {
            throw new Error(`package file changed while authenticating: ${rel}`);
          }
          const digest = packageIntegrity(bytes);
          records.push([rel, digest]);
          digests.set(rel, digest);
        } else {
          throw new Error(`package content contains an unsupported file type: ${rel}`);
        }
      }
    }

    await walk(directory, '');
    const rootAfter = await fs.lstat(directory, { bigint: true });
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
