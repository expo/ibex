import { babel } from '@rollup/plugin-babel';
import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    emptyOutDir: false,
    lib: {
      entry: resolve(__dirname, '../packages/ibex-runtime-js/src/runtime-entry.ts'),
      formats: ['iife'],
      name: 'IbexRuntime',
      fileName: () => 'runtime.js',
    },
    minify: 'terser',
    outDir: 'dist',
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
    sourcemap: false,
    terserOptions: {
      compress: {
        drop_console: false,
        passes: 2,
      },
      format: {
        comments: false,
      },
      mangle: {
        keep_classnames: true,
      },
    },
  },
  plugins: [
    babel({
      babelHelpers: 'bundled',
      extensions: ['.js', '.ts', '.tsx'],
      presets: [
        [
          '@babel/preset-env',
          {
            modules: false,
            targets: {
              ie: '11',
            },
          },
        ],
      ],
    }),
  ],
});
