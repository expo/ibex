import { describe, expect, test } from 'bun:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { packageIntegrity } from './capsec-policy-authoring.mjs';
import { authenticateAnalyzedPackageTree } from './policy-package-snapshot.mjs';

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
      expect(integrity).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/u);
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });
});
