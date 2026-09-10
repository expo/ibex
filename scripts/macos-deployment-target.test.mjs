#!/usr/bin/env node
// @ref LLP 0005#c-compilation — inspect emitted objects, not compiler flag strings.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.platform !== 'darwin') {
  console.log('macOS deployment targets: skipped (requires Apple compiler and Mach-O tools)');
  process.exit(0);
}
const scratch = await mkdtemp(join(tmpdir(), 'ibex-deployment-target-'));
const failures = [];
async function run(program, args, env, cwd = repo) {
  return (await exec(program, args, { cwd, env, maxBuffer: 16 * 1024 * 1024 })).stdout;
}
async function files(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...await files(path));
    else found.push(path);
  }
  return found;
}
function version(value) {
  return value.split('.').map(Number).concat([0, 0]).slice(0, 3).join('.');
}
async function minimum(path, env) {
  const output = await run('xcrun', ['otool', '-l', path], env);
  const values = [...output.matchAll(/cmd LC_(?:BUILD_VERSION|VERSION_MIN_MACOSX)[\s\S]*?\n\s*(?:minos|version) ([0-9.]+)/g)];
  assert.equal(values.length, 1, `one macOS minimum in ${path}: ${output}`);
  return version(values[0][1]);
}
try {
  const rustc = process.env.RUSTC || 'rustc';
  const cargo = process.env.CARGO || 'cargo';
  const host = (await run(rustc, ['-vV'], process.env)).match(/^host: (.+)$/m)[1];
  const crate = join(scratch, 'crates/ibex2');
  await mkdir(join(crate, 'src/engine'), { recursive: true });
  await mkdir(join(scratch, 'build_support'));
  await cp(join(repo, 'crates/ibex2/build.rs'), join(crate, 'build.rs'));
  // The production build script is run unchanged, with only its Rust runtime
  // replaced by a tiny executable. No engine or Oxc download is needed.
  await cp(join(repo, 'build_support/macos_deployment_target.rs'), join(scratch, 'build_support/macos_deployment_target.rs'));
  for (const name of ['darwin_http.mm', 'darwin_keychain.mm']) {
    await cp(join(repo, 'crates/ibex2/src/engine', name), join(crate, 'src/engine', name));
  }
  await writeFile(join(crate, 'Cargo.toml'), `[package]
name = "deployment-probe"
version = "0.0.0"
edition = "2021"
[build-dependencies]
cc = "1"
sha2 = "0.10"
`);
  await writeFile(join(crate, 'src/main.rs'), 'fn main() {}\n');
  await writeFile(join(scratch, 'Cargo.toml'), '[workspace]\nmembers = ["crates/*"]\nresolver = "2"\n');
  // The same helper covers the legacy runtime's C ABI/Brotli and C++ builds,
  // independent of the actual Ibex 2 Objective-C++ build script above.
  const native = join(scratch, 'crates/native');
  await mkdir(join(native, 'src'), { recursive: true });
  await writeFile(join(native, 'Cargo.toml'), `[package]
name = "native-probe"
version = "0.0.0"
edition = "2021"
[build-dependencies]
cc = "1"
`);
  await writeFile(join(native, 'build.rs'), `#[path = "../../build_support/macos_deployment_target.rs"]
mod macos_deployment_target;
fn main() {
    macos_deployment_target::align();
    cc::Build::new().file("src/probe.c").compile("probe_c");
    cc::Build::new().cpp(true).file("src/probe.cc").compile("probe_cpp");
}
`);
  await writeFile(join(native, 'src/probe.c'), 'int probe_c(void) { return 12; }\n');
  await writeFile(join(native, 'src/probe.cc'), 'extern "C" int probe_cpp() { return 15; }\n');
  await writeFile(join(native, 'src/main.rs'), `extern "C" { fn probe_c() -> i32; fn probe_cpp() -> i32; }
fn main() { unsafe { assert_eq!(probe_c() + probe_cpp(), 27); } }
`);
  // Reuse the same Cargo output directory: each change must invalidate the
  // native objects, including returning from an explicit target to the default.
  for (const requested of [undefined, '12.0', '14.0', '15.0', undefined]) {
    const label = requested ?? 'rustc default';
    try {
      const env = { ...process.env, CARGO_TARGET_DIR: join(scratch, 'target') };
      delete env.MACOSX_DEPLOYMENT_TARGET;
      if (requested) env.MACOSX_DEPLOYMENT_TARGET = requested;
      const selected = (await run(rustc, ['--target', host, '--print', 'deployment-target'], env)).trim();
      const expected = version(selected.split('=')[1]);
      const result = await exec(cargo, ['build', '--workspace', '--manifest-path', join(scratch, 'Cargo.toml'), '--target', host],
        { cwd: repo, env, maxBuffer: 16 * 1024 * 1024 });
      assert.doesNotMatch(result.stderr, /built for newer|overriding.*version-min/);
      const objects = (await files(join(scratch, 'target', host, 'debug/build')))
        .filter(path => /(?:darwin_(?:http|keychain)|probe)\.o$/.test(path));
      assert.equal(objects.length, 4, 'C, C++ and both real Objective-C++ objects were built');
      for (const path of [...objects, join(scratch, 'target', host, 'debug/deployment-probe'), join(scratch, 'target', host, 'debug/native-probe')]) {
        assert.equal(await minimum(path, env), expected, `${label}: ${path}`);
      }
      console.log(`PASS ${label}: Rust executables and C/C++/Objective-C++ objects = ${expected}`);
    } catch (error) {
      failures.push(`${label}: ${error.stack}\n${error.stderr ?? ''}`);
    }
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}
for (const failure of failures) console.error(failure);
assert.equal(failures.length, 0, `${failures.length} deployment-target cases failed`);
