# Windows `ibex2 run` turns non-ASCII string literals into `?`

**Status:** Open
**Systems:** Engine, Build
**Severity:** P2
**Author:** Claude (Opus 5.5), found during lane I1 (LLP 0057.000 §5.1.1)
**Date:** 2026-10-06

On Windows the release `ibex2` CLI runs a source entry whose string literal
`"\u00e9"` (an ASCII-only file using a JavaScript escape) as `"?"`
(U+003F). The same character built at run time is correct, so the engine and
its Unicode backend are fine. Something on the CLI's source path loses it:
the loader's lowering/codegen, the hand-off to `hermesc`, or a code-page
conversion. That is a guess, not a diagnosis.

Repro (Windows 11 25H2, i1 branch at its Windows Intl commits, release
`ibex2.exe` with and without `--features intl`, identical result):

```js
console.log(
  String.fromCharCode(0xe9).toUpperCase().charCodeAt(0).toString(16), // c9
  "\u00e9".charCodeAt(0).toString(16),                                 // 3f, expected e9
);
```

`Hermes::eval` with the same literal is correct (the `intl_engine` and
`intl_case` tests use non-ASCII literals through `eval` and pass on Windows).
A literal `"\u0130"` comparison in an Intl smoke script failed the same way,
which is how this was found. It is unrelated to Ibex's Intl shims.

`--no-compile` gives the same `3f`. The machine's ANSI code page is 1252,
which cannot be the whole story, because é exists in 1252. Next step: run
the loader's output through `hermesc` directly to find which stage replaces
the character.
