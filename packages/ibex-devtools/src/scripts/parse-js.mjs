// @ref LLP 0007#summary — devtools parsing rides the Rolldown/Oxc toolchain.
import { parseSync } from 'rolldown/utils';

export function parseModule(source, options = {}) {
  return parseWithOxc(source, 'module', 'module.js', options);
}

export function parseScript(source, options = {}) {
  return parseWithOxc(source, 'commonjs', 'script.js', options);
}

export function parseModuleOrScript(source, options = {}) {
  return parseModule(source, options) || parseScript(source, options);
}

function parseWithOxc(source, sourceType, fileName, { locations = false } = {}) {
  try {
    const parsed = parseSync(fileName, source, {
      lang: 'js',
      sourceType,
      range: true,
      preserveParens: false,
    });
    if (parsed.errors && parsed.errors.length) {
      return null;
    }
    if (locations) {
      attachStartLocations(parsed.program, source);
    }
    return parsed.program;
  } catch {
    return null;
  }
}

function attachStartLocations(ast, source) {
  const lineStarts = [0];
  for (let i = 0; i < source.length; i += 1) {
    if (source.charCodeAt(i) === 10) {
      lineStarts.push(i + 1);
    }
  }
  const locate = (offset) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (lineStarts[mid] <= offset) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    const lineIndex = Math.max(0, hi);
    return {
      line: lineIndex + 1,
      column: offset - lineStarts[lineIndex],
    };
  };
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const child of node) visit(child);
      return;
    }
    if (typeof node.type === 'string' && typeof node.start === 'number') {
      node.loc = {
        start: locate(node.start),
        end: locate(typeof node.end === 'number' ? node.end : node.start),
      };
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range') continue;
      const value = node[key];
      if (value && typeof value === 'object') visit(value);
    }
  };
  visit(ast);
}
