import { describe, expect, test } from 'bun:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { packageIntegrity } from './capsec-policy-authoring.mjs';
import {
  authenticateAnalyzedPackageTree,
  packageTreeSnapshot,
} from './policy-package-snapshot.mjs';

const symlinkTest = process.platform === 'win32' ? test.skip : test;

describe('policy package analysis/content join', () => {
  test('rejects an analysis-A to executable-tree-B substitution', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-race-'));
    try {
      const manifestBytes = Buffer.from('{"name":"pkg","version":"1.0.0"}\n');
      const analyzedSource = Buffer.from("module.exports = require('safe-dependency');\n");
      await fs.writeFile(path.join(directory, 'package.json'), manifestBytes);
      await fs.writeFile(path.join(directory, 'index.js'), analyzedSource);
      const analysis = {
        manifestBytes,
        manifest: JSON.parse(manifestBytes),
        sources: new Map([['index.js', packageIntegrity(analyzedSource)]]),
      };

      // Deterministic A→B barrier: the analyzed bytes requested only the safe
      // edge; B asks for wider behavior before integrity is assigned.
      await fs.writeFile(
        path.join(directory, 'index.js'),
        "module.exports = require('privileged-dependency');\n",
      );
      await expect(authenticateAnalyzedPackageTree(directory, analysis)).rejects.toThrow(
        'differs from the bytes used during graph analysis',
      );
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });

  test('accepts one stable tree and returns its integrity identity', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-stable-'));
    try {
      const manifestBytes = Buffer.from('{"name":"pkg","version":"1.0.0"}\n');
      const source = Buffer.from('module.exports = 1;\n');
      await fs.writeFile(path.join(directory, 'package.json'), manifestBytes);
      await fs.writeFile(path.join(directory, 'index.js'), source);
      const integrity = await authenticateAnalyzedPackageTree(directory, {
        manifestBytes,
        manifest: JSON.parse(manifestBytes),
        sources: new Map([['index.js', packageIntegrity(source)]]),
      });
      expect(integrity).toBe(
        packageIntegrity(
          JSON.stringify([
            ['index.js', packageIntegrity(source)],
            ['package.json', packageIntegrity(manifestBytes)],
          ]),
        ),
      );
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });

  symlinkTest('authenticates stable package-internal file and directory symlinks', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-links-'));
    try {
      const manifestBytes = Buffer.from('{"name":"pkg","version":"1.0.0"}\n');
      const source = Buffer.from('module.exports = 1;\n');
      await fs.mkdir(path.join(directory, 'lib', 'deep'), { recursive: true });
      await fs.writeFile(path.join(directory, 'package.json'), manifestBytes);
      await fs.writeFile(path.join(directory, 'lib', 'index.js'), source);
      await fs.symlink('lib/index.js', path.join(directory, 'alias.js'));
      await fs.symlink('lib/deep', path.join(directory, 'deep-link'), 'dir');
      await fs.symlink('lib', path.join(directory, 'linked-lib'), 'dir');
      await fs.symlink(
        'deep-link/../index.js',
        path.join(directory, 'parent-sensitive.js'),
      );

      const sourceDigest = packageIntegrity(source);
      const integrity = await authenticateAnalyzedPackageTree(directory, {
        manifestBytes,
        manifest: JSON.parse(manifestBytes),
        sources: new Map([
          ['alias.js', sourceDigest],
          ['linked-lib/index.js', sourceDigest],
          ['parent-sensitive.js', sourceDigest],
        ]),
      });

      expect(integrity).toBe(
        packageIntegrity(
          JSON.stringify([
            ['alias.js', `symlink-${packageIntegrity(Buffer.from('lib/index.js'))}`],
            ['deep-link', `symlink-${packageIntegrity(Buffer.from('lib/deep'))}`],
            ['lib/index.js', sourceDigest],
            ['linked-lib', `symlink-${packageIntegrity(Buffer.from('lib'))}`],
            ['package.json', packageIntegrity(manifestBytes)],
            [
              'parent-sensitive.js',
              `symlink-${packageIntegrity(Buffer.from('deep-link/../index.js'))}`,
            ],
          ]),
        ),
      );
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });

  symlinkTest('binds raw link targets even when both targets have identical bytes', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-retarget-'));
    try {
      const source = Buffer.from('module.exports = 1;\n');
      await fs.writeFile(path.join(directory, 'one.js'), source);
      await fs.writeFile(path.join(directory, 'two.js'), source);
      await fs.symlink('one.js', path.join(directory, 'entry.js'));
      const first = await packageTreeSnapshot(directory);

      await fs.unlink(path.join(directory, 'entry.js'));
      await fs.symlink('two.js', path.join(directory, 'entry.js'));
      const second = await packageTreeSnapshot(directory);

      expect(second.integrity).not.toBe(first.integrity);
      expect(second.digests.get('entry.js')).toBe(first.digests.get('entry.js'));
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });

  symlinkTest('records but does not absorb source outside the package defining tree', async () => {
    const project = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-principal-'));
    const directory = path.join(project, 'package');
    try {
      await fs.mkdir(directory);
      await fs.writeFile(path.join(directory, 'package.json'), '{}\n');
      await fs.writeFile(path.join(project, 'first-party.js'), 'first\n');
      await fs.symlink('../first-party.js', path.join(directory, 'root-source.js'));
      const first = await packageTreeSnapshot(directory);

      await fs.writeFile(path.join(project, 'first-party.js'), 'second\n');
      const second = await packageTreeSnapshot(directory);

      expect(second.integrity).toBe(first.integrity);
      expect(second.digests.has('root-source.js')).toBe(false);
    } finally {
      await fs.rm(project, { recursive: true, force: true });
    }
  });

  symlinkTest('refuses symlink cycles and chains beyond the fixed depth bound', async () => {
    const cycleDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-cycle-'));
    const depthDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'ibex-policy-depth-'));
    try {
      await fs.symlink('b', path.join(cycleDirectory, 'a'));
      await fs.symlink('a', path.join(cycleDirectory, 'b'));
      await expect(packageTreeSnapshot(cycleDirectory)).rejects.toThrow(
        'package symlink cycle while authenticating',
      );

      await fs.writeFile(path.join(depthDirectory, 'target.js'), 'module.exports = 1;\n');
      for (let index = 32; index >= 0; index -= 1) {
        const name = `link-${String(index).padStart(2, '0')}`;
        const target =
          index === 32 ? 'target.js' : `link-${String(index + 1).padStart(2, '0')}`;
        await fs.symlink(target, path.join(depthDirectory, name));
      }
      await expect(packageTreeSnapshot(depthDirectory)).rejects.toThrow(
        'package symlink depth exceeds 32',
      );
    } finally {
      await fs.rm(cycleDirectory, { recursive: true, force: true });
      await fs.rm(depthDirectory, { recursive: true, force: true });
    }
  });
});
