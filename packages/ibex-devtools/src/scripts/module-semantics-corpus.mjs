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
  },
]);

// LLP 0028 Phase 0 extends the same fixture owner with the transform-specific
// rows that gate the Oxc pin. These are separate from the frozen legacy-loader
// baseline above because each row is executed through both native source and
// prepared profiles, with an execution receipt proving which artifact ran.
// @ref LLP 0028#5-conformance-gates-telemetry-and-rollout
export const moduleTransformCorpus = Object.freeze([
  {
    id: 'typescript-enum',
    category: 'typescript-runtime',
    entry: { node: 'entry.mjs', ibex: 'entry.ts' },
    files: {
      'entry.mjs': `const Color = { Red: 1, Blue: 2 }; console.log(${JSON.stringify(marker)} + Color.Blue);\n`,
      'entry.ts': `enum Color { Red = 1, Blue = 2 } print(${JSON.stringify(marker)} + Color.Blue);\n`,
    },
    oracle: [`${marker}2`],
  },
  {
    id: 'typescript-namespace',
    category: 'typescript-runtime',
    entry: { node: 'entry.mjs', ibex: 'entry.ts' },
    files: {
      'entry.mjs': `const Box = { answer: 42 }; console.log(${JSON.stringify(marker)} + Box.answer);\n`,
      'entry.ts': `namespace Box { export const answer = 42; } print(${JSON.stringify(marker)} + Box.answer);\n`,
    },
    oracle: [`${marker}42`],
  },
  {
    id: 'typescript-import-equals',
    category: 'typescript-runtime',
    entry: { node: 'entry.cjs', ibex: 'entry.cts' },
    files: {
      'entry.cjs': `const dep = require('./dep.cjs'); console.log(${JSON.stringify(marker)} + dep.answer);\n`,
      'entry.cts': `import dep = require('./dep.cjs'); print(${JSON.stringify(marker)} + dep.answer);\n`,
      'dep.cjs': `exports.answer = 42;\n`,
    },
    oracle: [`${marker}42`],
  },
  {
    id: 'jsx-classic-runtime',
    category: 'jsx-configuration',
    entry: { node: 'entry.mjs', ibex: 'entry.tsx' },
    files: {
      'entry.mjs': `const value = { type: 'section', props: { title: 'ok' }, child: 42 }; console.log(${JSON.stringify(marker)} + JSON.stringify(value));\n`,
      'entry.tsx': `
type Props = { title: string };
const React = { createElement(type: string, props: Props, child: number) { return { type, props, child }; } };
const value = <section title="ok">{42}</section>;
print(${JSON.stringify(marker)} + JSON.stringify(value));
`,
    },
    oracle: [`${marker}{"type":"section","props":{"title":"ok"},"child":42}`],
  },
  {
    id: 'type-only-edges-erased',
    category: 'type-only-edges',
    entry: { node: 'entry.mjs', ibex: 'entry.ts' },
    files: {
      'entry.mjs': `console.log(${JSON.stringify(marker)} + 'erased');\n`,
      'entry.ts': `import type { Missing } from './types.ts'; export type { Missing }; print(${JSON.stringify(marker)} + 'erased');\n`,
      'types.ts': `export interface Missing { value: string }\n`,
    },
    oracle: [`${marker}erased`],
  },
  {
    id: 'native-esm-commonjs-interop',
    category: 'esm-commonjs-interop',
    entry: { node: 'entry.mjs', ibex: 'entry.mjs' },
    files: {
      'entry.mjs': `import value, { answer } from './dep.cjs'; const emit = typeof print === 'function' ? print : console.log; emit(${JSON.stringify(marker)} + JSON.stringify({ value: value.answer, answer }));\n`,
      'dep.cjs': `exports.answer = 42;\n`,
    },
    oracle: [`${marker}{"value":42,"answer":42}`],
  },
  {
    id: 'native-top-level-await',
    category: 'top-level-await',
    entry: { node: 'entry.mjs', ibex: 'entry.mjs' },
    files: {
      'entry.mjs': `await Promise.resolve(); const emit = typeof print === 'function' ? print : console.log; emit(${JSON.stringify(marker)} + 'settled');\n`,
    },
    oracle: [`${marker}settled`],
  },
  {
    id: 'dynamic-import-and-import-meta',
    category: 'dynamic-import',
    entry: { node: 'entry.mjs', ibex: 'entry.mjs' },
    files: {
      'entry.mjs': `const dep = await import('./dep.mjs'); const emit = typeof print === 'function' ? print : console.log; emit(${JSON.stringify(marker)} + JSON.stringify({ value: dep.value, url: import.meta.url.endsWith('/entry.mjs') }));\n`,
      'dep.mjs': `export const value = 7;\n`,
    },
    oracle: [`${marker}{"value":7,"url":true}`],
  },
  {
    id: 'oxc-diagnostic-original-source',
    category: 'diagnostics',
    entry: { node: 'entry.mjs', ibex: 'entry.ts' },
    files: {
      'entry.mjs': `console.log(${JSON.stringify(marker)} + 'oracle');\n`,
      'entry.ts': `const broken: number = ;\n`,
    },
    oracle: [`${marker}oracle`],
    native: { outcome: 'error', stderrIncludes: 'Oxc parse failed for' },
  },
  {
    id: 'composed-source-map-original-line',
    category: 'source-maps',
    entry: { node: 'entry.mjs', ibex: 'entry.ts' },
    files: {
      'entry.mjs': `try { await import('./thrower.mjs'); } catch (error) { const match = /thrower\\.mjs:(\\d+)/.exec(String(error && error.stack)); console.log(${JSON.stringify(marker)} + 'line=' + (match ? match[1] : 'none')); }\n`,
      'thrower.mjs': `// line 1\n// line 2\n// line 3\n// line 4\nthrow new Error('source-map-line');\n`,
      'entry.ts': `await import('./thrower.ts');\n`,
      'thrower.ts': `// line 1\n// line 2\n// line 3\n// line 4\nthrow new Error('source-map-line');\n`,
    },
    oracle: [`${marker}line=5`],
    native: { outcome: 'error', stderrIncludes: 'thrower.ts:5' },
  },
  {
    id: 'shim-delta-sloppy-commonjs',
    category: 'shim-runner-delta',
    entry: { node: 'entry.cjs', ibex: 'entry.cjs' },
    files: {
      'entry.cjs': `sloppyValue = 42; const emit = typeof print === 'function' ? print : console.log; emit(${JSON.stringify(marker)} + sloppyValue);\n`,
    },
    oracle: [`${marker}42`],
    native: {
      outcome: 'error',
      stderrIncludes: 'native CommonJS record evaluation refused',
      note: 'The native CapSec global refuses sloppy implicit-global creation that Node CommonJS permits; this is the pinned shim-to-runner behavior delta.',
    },
  },
  {
    id: 'cjs-passthrough',
    category: 'shim-runner-delta',
    entry: { node: 'entry.cjs', ibex: 'entry.cjs' },
    files: {
      'entry.cjs': `module.exports.answer = 42; const emit = typeof print === 'function' ? print : console.log; emit(${JSON.stringify(marker)} + module.exports.answer);\n`,
    },
    oracle: [`${marker}42`],
  },
]);
