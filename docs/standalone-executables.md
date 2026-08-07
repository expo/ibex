# Standalone executables

A catalog-pinned Ibex release can compile a JavaScript or TypeScript entry into
one executable containing the static Hermes runtime, the complete admitted
module graph, HBC carriers, production policy, and provenance:

```sh
ibex policy generate \
  --entry ./main.ts \
  --target-profile sfe-v1 \
  --target-triple aarch64-apple-darwin \
  --out ./ibex-policy.json

ibex compile ./main.ts \
  --policy ./ibex-policy.json \
  --output ./my-app

ibex inspect-executable ./my-app
./my-app first-argument
```

Use `x86_64-unknown-linux-gnu` for the Linux x64 release. Compilation is
host-target only in v1. The policy step is mandatory even though ordinary
launches do not enforce it; Ibex never silently invents the policy that a later
CapSec-selected launch would consume. Commit the generated policy with the
program so drift is reviewable.

Graphs containing invocation-time guarded shapes still compile by default, so
dead branches preserve the same timing as `ibex run`. The compiler prints a
deterministic list of every computed dynamic import without a candidate table,
computed CommonJS `require`, and unsupported dynamic-import options site. Use
`--deny-unsupported` to require a clean graph and refuse before producing an
output file:

```sh
ibex compile ./main.ts \
  --policy ./ibex-policy.json \
  --deny-unsupported \
  --output ./my-app
```

The result is self-contained with respect to Ibex, Hermes, application source,
and the release catalog. It still depends on the ordinary system libraries and
minimum OS baseline reported by `inspect-executable`. The detached
`<output>.provenance.json` is build evidence, not a runtime sidecar; copying
only the executable is sufficient to run it.

## Runtime authority

Standalone v1 uses ambient compatibility mode by default. The program has the
same filesystem, inherited-environment, network, subprocess, and other
authority as the user who launches it, subject only to whether that backend is
compiled into the target stub. A single-file executable is not, by itself, a
sandbox.

The same file reserves two exact first-position selectors. CapSec is the
monotonic fail-closed execution request:

```sh
./my-app --ibex-capsec app-argument
```

CapSec selection is monotonic and fail-closed. If the executable has no
accepted advertisement for its exact target contract, it exits before
application code instead of retrying in ambient mode. To pass the literal
selector to the application, escape stub option parsing:

```sh
./my-app -- --ibex-capsec
```

The second selector lets a recipient inspect the copied artifact without an
Ibex installation:

```sh
./my-app --ibex-info
```

It prints one canonical `ibex/standalone-executable-info/1` JSON report with
the authenticated default posture, selector rules, CapSec availability, target,
backend inventory, provenance kind, and admitted graph/contract identities,
then exits without constructing the application runtime or evaluating entry
code. Escape it in the same way when the application needs the literal word:

```sh
./my-app -- --ibex-info
```

Every other argument, including later occurrences of either selector, belongs
to the application. Both execution modes and the information action perform the same
envelope, contract, graph, policy, carrier, HBC, and provenance admission
before dispatch or reporting.

## Catalog availability

`ibex compile` accepts only the immutable content-addressed catalog whose
digest was compiled into that Ibex release. There is no command-line or
environment override for this trust root. A standalone-enabled release kit
contains four producer components: `ibex`, the equally pinned
`ibex-sfe-catalog` installer, one target-specific catalog archive, and an
adjacent `ibex-policy-toolchain-<digest>` directory. Install the archive before
the first compile using the exact command printed by Ibex:

```sh
tar -xzf ibex-sfe-catalog-<version>-<target>-<digest>.tar.gz
./ibex-sfe-catalog install --source <digest>
```

The installer does not accept a catalog digest from the command line. Its
trust root is compiled in alongside Ibex's, and it verifies the canonical
manifest, every content-addressed artifact, and the contract/compiler/stub
cross-bindings before atomically publishing the catalog to the user cache. A
generic checkout build without a release catalog intentionally refuses both
compilation and installation.

The policy-toolchain directory is producer-only. Its canonical manifest binds
the target and a closed inventory containing the exact Bun executable,
policy-authoring JavaScript, CapSec contract inputs, lockfile, and installed
package closure. The release `ibex` admits only the adjacent directory whose
digest was compiled into it, re-admits the inventory after policy generation,
and never falls back to `IBEX_REPO_ROOT`, a source checkout, or Bun/Node from
`PATH`. Keep that directory beside `ibex` while authoring policy. Neither it,
the catalog, nor Ibex itself is a sidecar for the resulting application; after
compilation, the copied application executable is the complete runnable
artifact.

Release builders use `scripts/build-sfe-release.sh` with explicit target,
minimum-platform, patched Hermes tools, static archives, and policy runner. It
emits the pinned producer, pinned installer, addressed catalog archive,
authenticated policy toolchain, and build/audit reports as one release kit; it
does not infer release provenance from `PATH`. The canonical stub contract is
staged at a content-addressed compiler-input path beneath the declared Cargo
target directory, so random assembly work directories cannot perturb the
native Rust/LLVM identity. Directory-derived Cargo watch sets are sorted, and
the release build fixes `SOURCE_DATE_EPOCH=1` so timestamp-bearing native
producers such as vendored OpenSSL do not inject wall-clock time into the stub.
The fixed `hermesc` recipe likewise uses stable relative input and output names:
Hermes records the source filename in HBC, so passing a random absolute work
path would otherwise perturb carrier and final-executable bytes.
For Linux, the builder derives the static Hermes include/lib selection from
the exact authenticated `hermesvm` archive instead of ambient build variables.
The Ubuntu 22.04 release lane installs `libicu-dev`, `pkg-config`, and
`zlib1g-dev` explicitly; the static runtime includes `zlib.h` directly and
must not depend on a runner image providing that header accidentally.
`scripts/check-sfe-release-kit.sh` then exercises catalog installation and the
final-recipient flow, including missing-catalog diagnostics, authenticated
inspection, relocation, real Fetch, top-level await, ESM/CommonJS/builtin and
literal/computed dynamic imports, every-section tamper refusal, and launch with
source and catalog unavailable. It also verifies the authenticated backend
inventory, a loopback `node:http` server round trip, the stable limitations for
unavailable HTTP/2, inspector, WASI, and worker backends, numeric
`process.exitCode`, immediate `process.exit`, foreground and detached
failures, unhandled rejection, and SIGINT/SIGTERM/SIGHUP statuses with bounded
output flush. It also launches the final image through a raw invalid UTF-8 OS
argument and requires a pre-entry refusal naming the offending index. Its
producer matrix compiles a graph containing all three guarded unsupported-site
classes, requires the default diagnostic and successful dead-branch execution,
then requires `--deny-unsupported` to refuse without publishing an output. Its
policy steps clear the environment, remove Bun and Node from
`PATH`, poison `IBEX_REPO_ROOT`, and prove that a release `ibex` separated from
its packaged toolchain refuses instead of finding a checkout fallback. A
candidate-kit receipt also removes an isolated producer installation before
transferring only a two-module TypeScript Fetch executable to a second
compatible host, where it runs without Ibex or Hermes. Publication of the
exact installation artifacts remains release work. An official Ubuntu 22.04
GLIBC 2.35 builder/recipient exercise has repeated the same test with only the
final executable copied into a fresh recipient root and no Ibex, Hermes,
source, catalog, or Ibex cache present. Two physical Ubuntu 22.04 builders also
produced identical catalog, contract, policy-toolchain, native-stub, compile
plan, and unsigned application identities, with the complete release-kit
matrix green on both. `scripts/check-sfe-reproducibility.sh` is the strict
comparator for those identities. Each evidence directory also contains an
`ibex/sfe-builder-receipt/1` record binding its logical builder identity, exact
Git commit/tree and clean-source state, host tuple, Rust/Cargo, C compiler,
linker, and (on macOS) Xcode/SDK versions. The v2 comparison requires distinct
builder identities, identical clean source and toolchains, and identical
unsigned artifact identities. CI gives each supported tuple two independent
clean build jobs and rejects any mismatch rather than choosing a preferred
artifact.

On macOS the release-kit gate also checks the final `LC_BUILD_VERSION` against
the authenticated catalog baseline and exercises signature replacement on a
completed application: it removes the ad-hoc signature, requires the same
authenticated graph and CompilePlan identities, re-signs with the system
signer using the hardened-runtime option, verifies the replacement strictly,
and runs the relocated application through Fetch after source/catalog
withdrawal. This is structural and ad-hoc signing evidence, not a Developer ID,
secure-timestamp, or notarization receipt; those publisher steps remain
required for a distributed macOS release.

`ibex inspect-executable` never evaluates application code. It authenticates
the embedded boot contract and reports the default mode, both selectors, CapSec
availability, target baseline, graph/carrier admission, signature state, and
provenance independently. Its backend inventory is authenticated by the V2
stub contract and distinguishes available, limited, and unavailable surfaces,
including the exact target implementation and any stable limitation text. Its
machine report is `ibex/executable-inspection/3`; the authenticated stub
contract carrying these fields is `ibex/stub-contract/3`.
For release provenance it also reconstructs the actual signature-stripped
catalog stub from the outer executable and rehashes it. `stubCoreConsistency`
therefore detects an outer-stub mutation independently from inner-envelope,
platform-signature, and publisher-attestation state; it is not merely the
digest string claimed by embedded provenance.

## Release performance evidence

Standalone release measurements use
`packages/ibex-devtools/src/scripts/benchmark-sfe-release.mjs`. The collector
will not start sampling unless one canonical budget document covers both
`aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`, has `status: "accepted"`
with an author/date/rationale, is tracked in Git, exactly matches its `HEAD`
blob, and the rest of the tracked source tree is clean. This is deliberate:
the numeric limits must be reviewable and fixed before anyone sees the release
measurements.

Each target row fixes at least five samples, the literal startup protocol
`fresh-process-os-cache-uncontrolled-v1`, record-count constraints that keep
the hello and large-graph workloads distinct, and numeric maxima for:

- hello-world, large-graph, and diagnostic factory-table executable sizes;
- fresh-process hello-world, large-graph, and factory-table median startup;
- an HBC relocation profile whose timer includes both copying to a unique path
  and launching it;
- full `inspect-executable` median time, including footer/signature and
  stub-core verification; and
- the maximum dynamic dependency count of any measured executable.

The protocol starts a new process for every sample but does not claim that the
OS page cache was evicted. The raw samples, exact artifact digests and sizes,
dependency inventories, host/toolchain identity, committed budget blob,
source revision, thresholds, actuals, and named failures are all retained in
the versioned report. Before timing begins, the collector also inspects every
input. Both HBC artifacts must be admitted release-v1 envelopes from the same
catalog/stub/producer family with static-HBC CompilePlans and the exact target
baseline; the factory-table artifact must use the separate development
producer, diagnostic target profile, and non-release provenance. Their
authenticated record counts must satisfy the precommitted workload bounds.
The factory-table row is diagnostic evidence only; its budget value remains
`undecided-pending-measurement` and does not silently promote that carrier to
release eligibility.

After the author has committed the two-tuple budget document, collect a report
on each matching release host with:

```sh
bun run benchmark:sfe-release -- \
  --budgets config/sfe-performance-budgets.json \
  --ibex /path/to/release-kit/ibex \
  --hello-hbc /path/to/hello-hbc \
  --large-graph-hbc /path/to/large-graph-hbc \
  --hello-factory-table /path/to/diagnostic-hello-factory-table \
  --hello-output 'HELLO_OK' \
  --large-graph-output 'LARGE_GRAPH_OK' \
  --factory-table-output 'HELLO_OK' \
  --target aarch64-apple-darwin \
  --write /path/to/sfe-performance-macos.json
```

The normal release producer continues to refuse factory-table output. The
factory-table input above is therefore an explicitly diagnostic development
artifact, not something that may be substituted into a release kit. Supplying
`--host-contention-observed` preserves the measurements but makes the gate
fail; such a report is provenance, not release evidence. Numeric budgets and
final measurements have not yet been selected or recorded.

Build that diagnostic input with the same full static Hermes archive family as
the target release stub, but through the deliberately non-release development
contract:

```sh
scripts/build-sfe-diagnostic-factory-table.sh \
  --target aarch64-apple-darwin \
  --hermes tools/hermes/hermes \
  --static-archive hermesvm ios/Frameworks/macos-static/libhermesvm_a.a \
  --static-archive jsi ios/Frameworks/macos-static/libjsi.a \
  --static-archive boost-context ios/Frameworks/macos-static/libboost_context.a \
  --entry ./hello.mjs \
  --output /path/to/diagnostic-hello-factory-table
```

The builder verifies that the result uses development provenance, the
diagnostic host contract, complete inner admission, and paired carrier
sections. It never writes the artifact into a release kit, and `ibex compile
--carrier factory-table` remains a hard refusal.
