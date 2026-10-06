# Windows `ibex2 run` turns non-ASCII string literals into `?`

**Status:** Closed (2026-10-06): not an Ibex bug; the `?` was in the source file
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

## Resolution (2026-10-06, lane S3)

Not an Ibex bug, on Windows or anywhere else. The `?` was written into the file
before `ibex2` ever read it. The repro script (`wini1_tr.ps1` on the NucBox) was
generated on the Mac, where the shell turned the JavaScript escape `\u00e9` into a
raw UTF-8 `é` (bytes `c3 a9`). Windows PowerShell 5.1 reads a BOM-less `.ps1` in
the ANSI code page (two characters, `Ã©`), and the script then wrote the module
with `Set-Content -Encoding ascii`, which replaces each non-ASCII character with
`?`. The generated `tr2.js` contains `"??"` (bytes `22 3f 3f 22`). So the file was
not ASCII-only with an escape, as filed. `Hermes::eval` looked correct because
those tests are Rust source, which never passes through PowerShell.

Checked on the NucBox with the I1 release binary and with main `ec949fe`. A
UTF-8 file run through `ibex2 run`, `--no-compile`, `build`, and `--precompiled`
keeps `"\u00e9"`, `"\u0130"`, a raw `é`, `"\u{1F600}"`, `"\uD83D\uDE00"`, and a
raw `😀`. Each path hands the bytes on unchanged: the loader reads UTF-8
(`read_to_string`, and invalid UTF-8 is refused, not replaced), ESM lowering
splices text, TypeScript stripping goes through oxc codegen, the hermesc
hand-off writes the wrapper with `std::fs::write`, and the shim gives Hermes the
bytes. `Set-Content` without `-Encoding` writes cp1252 `é` as byte `e9`, which
`ibex2` refuses as invalid UTF-8. `\u0130` best-fits to `I`.

Regression test: `the_cli_keeps_non_ascii_string_literals` in
`crates/ibex2-runtime/tests/loader.rs` runs the built CLI. Its entry is
`entrée.js` (a non-ASCII argv), it imports a `.ts` module, it runs every leg
(the compiled legs only when the CLI can build), and it checks the UTF-16 code
units and the UTF-8 bytes on stdout. Passes on Windows and macOS. The README's
Windows section now says that sources are UTF-8 and explains what PowerShell 5.1
writes instead.
