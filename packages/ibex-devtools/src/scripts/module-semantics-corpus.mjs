/**
 * Implementation-neutral module-semantics corpus for LLP 0026 Phase 0.
 *
 * Each fixture is a small project. `files` are shared by the Node oracle and
 * Ibex/Hermes unless a runtime-specific override is supplied. Observable
 * results are lines prefixed with MODULE_SEMANTICS| so diagnostic logging from
 * either runtime cannot accidentally become part of the semantic contract.
 *
 * @ref LLP 0026#phase-0-baseline-the-current-contract — one corpus records the
 * current path's divergences before the module runner changes evaluation.
 */

const marker = 'MODULE_SEMANTICS|';

export const moduleSemanticsMarker = marker;

export const moduleSemanticsCorpus = Object.freeze([
  {
    id: 'esm-live-binding-mutation',
    category: 'live-bindings',
    note: 'An imported binding observes writes performed by its declaring module.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
import { value, increment } from './dep.mjs';
const before = value;
increment();
console.log(${JSON.stringify(marker)} + JSON.stringify({ before, after: value }));
`,
      'dep.mjs': `
export let value = 0;
export function increment() { value += 1; }
`,
    },
    oracle: [`${marker}{"before":0,"after":1}`],
  },
  {
    id: 'esm-direct-cycle',
    category: 'cycles',
    note: 'A direct cycle instantiates both modules before evaluation and keeps live views.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
import { readA, readB } from './a.mjs';
console.log(${JSON.stringify(marker)} + JSON.stringify([readA(), readB()]));
`,
      'a.mjs': `
import { b, readAFromB } from './b.mjs';
export let a = 'a0';
export function readA() { return a; }
export function readB() { return b + ':' + readAFromB(); }
a = 'a1';
`,
      'b.mjs': `
import { a } from './a.mjs';
export let b = 'b0';
export function readAFromB() { return a; }
b = 'b1';
`,
    },
    oracle: [`${marker}["a1","b1:a1"]`],
  },
  {
    id: 'esm-namespace-shape',
    category: 'namespaces',
    note: 'Namespace key order, null prototype, tag, and non-extensibility are observable.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
import * as ns from './dep.mjs';
console.log(${JSON.stringify(marker)} + JSON.stringify({
  keys: Object.keys(ns),
  extensible: Object.isExtensible(ns),
  nullPrototype: Object.getPrototypeOf(ns) === null,
  tag: ns[Symbol.toStringTag] || null,
}));
`,
      'dep.mjs': `
export const z = 3;
export default 1;
export const a = 2;
`,
    },
    oracle: [`${marker}{"keys":["a","default","z"],"extensible":false,"nullPrototype":true,"tag":"Module"}`],
  },
  {
    id: 'esm-commonjs-namespace',
    category: 'esm-commonjs-interop',
    note: 'The Node-24 CJS namespace includes default and module.exports views.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
import value, * as ns from './dep.cjs';
console.log(${JSON.stringify(marker)} + JSON.stringify({ value, keys: Object.keys(ns), same: ns.default === ns['module.exports'] }));
`,
      'dep.cjs': `module.exports = { answer: 42 };\n`,
    },
    oracle: [`${marker}{"value":{"answer":42},"keys":["default","module.exports"],"same":true}`],
  },
  {
    id: 'dependency-top-level-await-order',
    category: 'top-level-await',
    note: 'An importer waits for dependency TLA before its body evaluates.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
import { trace } from './dep.mjs';
console.log(${JSON.stringify(marker)} + JSON.stringify(trace.concat('entry')));
`,
      'dep.mjs': `
const trace = ['dep:start'];
await Promise.resolve();
trace.push('dep:end');
export { trace };
`,
    },
    oracle: [`${marker}["dep:start","dep:end","entry"]`],
    currentIbex: {
      outcome: 'error',
      stderrIncludes: "';' expected",
      note: 'The current file-at-a-time fallback rejects this dependency TLA before producing an entry observation.',
    },
    currentIbexByPlatform: {
      win32: {
        outcome: 'silent',
        note: 'The Windows compatibility entry path exits zero without a semantic marker.',
      },
    },
  },
  {
    id: 'dynamic-import-settlement',
    category: 'dynamic-import',
    note: 'Dynamic import returns a promise and resolves to the stable namespace.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
const first = await import('./dep.mjs');
const second = await import('./dep.mjs');
console.log(${JSON.stringify(marker)} + JSON.stringify({ value: first.value, same: first === second }));
`,
      'dep.mjs': `export const value = 7;\n`,
    },
    oracle: [`${marker}{"value":7,"same":true}`],
  },
  {
    id: 'typescript-tsx-runtime',
    category: 'typescript-jsx',
    note: 'The same semantic program executes from TSX on Ibex and plain ESM on Node.',
    entry: { node: 'entry.mjs', ibex: 'entry.tsx' },
    files: {
      'entry.mjs': `
const React = { createElement(type, props, child) { return { type, props, child }; } };
const value = React.createElement('section', { title: 'ok' }, 42);
console.log(${JSON.stringify(marker)} + JSON.stringify(value));
`,
      'entry.tsx': `
type Props = { title: string };
const React = { createElement(type: string, props: Props, child: number) { return { type, props, child }; } };
const value = <section title="ok">{42}</section>;
console.log(${JSON.stringify(marker)} + JSON.stringify(value));
`,
    },
    oracle: [`${marker}{"type":"section","props":{"title":"ok"},"child":42}`],
  },
  {
    id: 'source-map-original-line',
    category: 'source-maps',
    note: 'A transformed dependency reports its original throw line.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
try { await import('./thrower.mjs'); }
catch (error) {
  const match = /thrower\\.mjs:(\\d+)/.exec(String(error && error.stack));
  console.log(${JSON.stringify(marker)} + 'line=' + (match ? match[1] : 'none'));
}
`,
      'thrower.mjs': `// line 1
// line 2
// line 3
// line 4
throw new Error('source-map-line');
`,
    },
    oracle: [`${marker}line=5`],
    currentIbex: {
      outcome: 'error',
      stderrIncludes: 'Invalid expression encountered',
      note: 'The current dynamic-import/TLA shim fails before the original-line observation can be produced.',
    },
  },
  {
    id: 'scanner-eng-22514-comments',
    category: 'scanner-regressions',
    issue: 'ENG-22514',
    note: 'Comment text containing module syntax cannot terminate or create a declaration.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
// export const phantom = "comment";
/* import phantom from './missing.mjs'; */
export const real = 14;
console.log(${JSON.stringify(marker)} + real);
`,
    },
    oracle: [`${marker}14`],
  },
  {
    id: 'scanner-eng-22520-strings',
    category: 'scanner-regressions',
    issue: 'ENG-22520',
    note: 'Quotes and module keywords inside strings do not affect statement scanning.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': `
const text = "export default 'not syntax'; // import";
export const length = text.length;
console.log(${JSON.stringify(marker)} + length);
`,
    },
    oracle: [`${marker}38`],
  },
  {
    id: 'scanner-eng-22528-regex-template',
    category: 'scanner-regressions',
    issue: 'ENG-22528',
    note: 'Regex and template contents cannot corrupt delimiter or comment state.',
    entry: 'entry.mjs',
    files: {
      'entry.mjs': [
        'const re = /["\'\\\\/]{2} export default/;',
        'const text = `prefix ${(() => { return \'import("missing")\'; })()} suffix`;',
        'export const ok = !re.test(text) && text.includes(\'missing\');',
        `console.log(${JSON.stringify(marker)} + ok);`,
        '',
      ].join('\n'),
    },
    oracle: [`${marker}true`],
  },
  {
    id: 'package-imports-key-order',
    category: 'resolution-divergences',
    note: 'Conditional imports use object key order and condition membership, not a fixed precedence.',
    entry: 'entry.mjs',
    files: {
      'package.json': JSON.stringify({
        type: 'module',
        imports: {
          '#branch': {
            default: './default.mjs',
            import: './import.mjs',
            require: './require.cjs',
          },
        },
      }, null, 2),
      'entry.mjs': `
import value from '#branch';
console.log(${JSON.stringify(marker)} + value);
`,
      'default.mjs': `export default 'default-first';\n`,
      'import.mjs': `export default 'import-branch';\n`,
      'require.cjs': `module.exports = 'require-branch';\n`,
    },
    oracle: [`${marker}default-first`],
    currentIbex: {
      outcome: 'error',
      stderrIncludes: 'Failed to resolve package import #branch',
      note: 'The shipped private-import resolver cannot consume this Node conditional-import map on the loader path.',
    },
    currentIbexByPlatform: {
      win32: {
        outcome: 'silent',
        note: 'The Windows compatibility entry path exits zero without a semantic marker.',
      },
    },
  },
]);
