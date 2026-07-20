# LLP 0034: Portable Engine Artifact Provenance

**Type:** RFC
**Status:** Draft
**Systems:** Security, Engine, Build, Distribution, CI, Runtime, Host ABI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-19
**Revised:** 2026-07-19 (Phase 0 now also freezes the source-tree, reviewed-
profile, header, export-policy, ABI, and host-tool compatibility inputs plus
the raw Sigstore bundle byte contract; authority remains disabled pending RFC
review, physical non-Apple dependency validation, and the Windows bridge spike)
**Related:** LLP 0001; LLP 0005; LLP 0013; LLP 0021; LLP 0032

## Summary

Ibex currently proves that conformance work on one machine used one exact
mapped Hermes file. That identity deliberately includes an absolute path and a
host-local file object. It is strong evidence within one runner, but two honest
runners can never compare equal. LLP 0032 therefore prohibits authoritative
cross-runner sharding and resumption until a portable provenance contract
exists.

This RFC separates two identities that currently share one JSON object:

1. a **portable engine artifact identity**, derived from an authenticated,
   exact-membership package manifest and identical on every runner; and
2. a **mapped engine instance identity**, proving that one process actually
   mapped the portable artifact it claims on its local operating system.

The build workflow authenticates a transport archive, the installer verifies
and materializes its exact payload into a content-addressed local store,
`build.rs` embeds the verified portable identity, and the runtime joins that
identity to the local mapped image. Conformance shards carry both identities.
The aggregate compares the portable identity across runners and validates each
runner's local mapping proof without requiring local paths or file IDs to be
equal.

The first portable authority is the existing no-debugger patched Hermes
Release package for `aarch64-apple-darwin`. Linux may adopt the same contract
independently. Windows remains unpromotable until Ibex replaces its current
pathname-reopen check with a load sequence that pins the DLL file object before
mapping and retains that pin for the process lifetime.

This changes how engine identity is represented and transported. It does not
relax any fixture, report, target-cell, or advertisement rule in LLP 0021, and
it does not make a diagnostic shard authoritative merely because its engine
package is portable.

## Motivation

### The current identity is intentionally local

`LoadedEngineBinaryIdentity` currently contains:

- the canonical engine path;
- the binary digest;
- the platform file-object identity (`dev`/`ino` or Windows volume/file ID);
- target architecture; and
- structural engine features.

On macOS, Ibex asks the kernel for the mapped region containing
`makeHermesRuntime`, compares that region's device/inode with a pinned file,
and hashes the pinned file. Linux performs the analogous `/proc/self/maps`
join. These are useful same-runner checks. A path and inode from runner A,
however, say nothing comparable about runner B.

The target advertisement currently embeds the complete loaded identity and
production startup requires byte-for-byte JSON equality. Consequently an
advertisement produced on CI would authorize only the incidental path and file
object from that CI machine. Copying the same authenticated bytes to a new
machine changes the identity and must fail.

### Most of the distribution authority already exists

The Hermes artifact workflow already builds from the pinned source and patch
authorities, publishes per-platform archives, and attaches GitHub build-
provenance attestations. The installers require the reviewed repository,
workflow, and `main` source ref; verify the transport; validate a profile
receipt; and fall back to source rather than accepting an unauthenticated
prebuilt.

That is a strong starting point, but it is not yet a portable runtime
contract:

- archive layout is validated by platform-specific scripts rather than one
  closed manifest schema;
- the build-provenance verification result is not retained as an input that a
  later aggregate can audit;
- the profile receipt identifies important components but not exact package
  membership;
- authoritative builds can still be selected through arbitrary local paths;
- conformance reports and advertisements serialize the host-local identity;
  and
- Windows identifies the current pathname object, not the image section that
  supplied already executing code.

### Cross-runner authority needs more than matching hashes

Two shards independently reporting the same SHA-256 string is not provenance.
The aggregate must know what package the digest names, which reviewed build
created it, how each runner authenticated it, which exact component was mapped,
and whether every shard belongs to the same suite plan and trusted CI run.
Portable engine identity is necessary for cross-runner authority, but remains
only one input to LLP 0032's exact-membership aggregate.

## Goals

- Give identical reviewed Hermes packages one stable identity across paths,
  filesystems, runners, and archive encodings.
- Preserve a target-local proof that the process mapped the exact runtime
  component named by that portable identity.
- Require every **consumer** to authenticate the complete package before any
  component is linked, loaded, executed, or admitted as conformance evidence.
  The reviewed publisher may execute newly built tools while validating its
  own output, but those executions create no consumer or conformance
  authority.
- Make target reports and advertisements free of absolute paths and host-local
  file IDs while retaining those facts in per-run evidence.
- Supply the portable identity needed by a future cross-runner design while
  retaining LLP 0032's same-runner authority until coordinator assignment,
  signer separation, and retry lineage are separately accepted.
- Provide a normal checkout-local installation path so developers do not need
  an artifact directory borrowed from another worktree.
- Define the additional Windows mapped-image gate rather than treating a
  portable archive digest as proof of already mapped code.

## Non-goals

- Reproducible Hermes builds. This RFC authenticates reviewed build provenance
  and exact output bytes; reproducibility can strengthen that authority later.
- Defending against a compromised kernel, hypervisor, GitHub OIDC issuer, or
  protected-branch administrator.
- Treating release assets, checksum sidecars, cache keys, filenames, or mirrors
  as trust anchors.
- Making self-hosted runners authoritative in the first rollout.
- Weakening the CapSec fixture inventory, converting broad suites into fixture
  passes, or bypassing target advertisement.
- Defining a general package format for Ibex applications or JavaScript module
  graphs.
- Making an engine artifact built for one target/profile satisfy another.

## Terminology

**Payload** is the exact set of files and permitted relative symlinks consumed
from an engine package.

**Transport archive** is a tar or zip encoding that carries only the payload
and manifest. Its digest authenticates that particular encoding; it is not the
portable artifact identity. Distribution provenance is detached so its signed
statement can bind the final archive digest without creating a digest cycle.

**Portable engine manifest** is the canonical, exact-field description of the
payload, target, engine profile, reviewed source/build authority, and runtime
interface.

**Portable artifact ID** is a domain-separated digest of the canonical
portable engine manifest with its `artifactId` field omitted. It is stable
across machines and may be stable across independently authenticated transport
encodings that carry byte-identical manifests and payloads.

**Mapped engine instance** is one process-local mapping of the runtime
component, joined to a platform file object and the portable artifact ID.

**Distribution provenance** is a verifiable signed statement binding a
transport digest to the reviewed publisher workflow and source revision.

**Shard provenance** is a verifiable signed statement binding one canonical
shard bundle to its trusted workflow job, suite run, plan, source, target,
portable artifact, and expected shard membership.

## Threat model and trust roots

The release service, mirror, network, archive filename, checksum sidecar, local
cache, environment variables, and pre-existing installation directories are
untrusted transport or storage.

V1 does not claim to defend an interactive developer checkout from another
malicious process already running as that developer. Read-only mode bits are
not a same-user security boundary. Promotion jobs instead run in fresh hosted
runner isolation, materialize a job-owned store, admit no concurrent untrusted
same-user process, and bind the exact build inputs and final executable bytes.
Supporting hostile same-user mutation requires an immutable filesystem
snapshot or a separately accepted brokered build design; it may not be inferred
from this RFC's content addressing.

The initial promotion trust roots are:

- the checked-in expected repository, publisher workflow path, and protected
  `refs/heads/main` source-ref policy;
- GitHub's OIDC-backed artifact-attestation verification root;
- GitHub-hosted runner isolation for the reviewed publisher, authoritative
  shards, and aggregate; and
- the reviewed Ibex source revision and suite plan.

Verification MUST reject a provenance statement from another repository,
workflow, ref, source revision, subject digest, or runner class. Mirrors may
carry bytes but cannot change those expected identities. Self-hosted builders
or conformance runners are diagnostic until a separate accepted trust policy
admits them.

The runner operating system is trusted to report mapped file objects and to
enforce file-handle sharing/locking semantics. Repository build and fixture
code is trusted but may fail or hang; LLP 0032's supervisor contains those
failures. JavaScript under evaluation is untrusted and receives no provenance
or loader control.

## Portable package contract

### Envelope layout

An authenticated transport contains exactly:

```text
payload/...
META-INF/portable-engine-manifest.json
```

The distribution-provenance bundle travels alongside the archive and is not
an archive member. The installer authenticates that detached bundle and its
subject digest before it parses or extracts the untrusted archive. A bundle
inside the bytes whose digest it attests would be a cyclic, unconstructible
contract and is forbidden.

The envelope validator rejects any additional top-level member. Payload paths
are UTF-8, slash-separated, relative, normalized, and unique both bytewise and
under one specified target-filesystem equivalence key. That key covers case
folding, Unicode normalization, and, on Windows, trailing-dot/space collapse,
reserved device names, and alternate-data-stream syntax. Empty segments, `.`
and `..`, absolute paths, drive/UNC/device prefixes, control characters,
device files, FIFOs, sockets, hard links, sparse expansion beyond the declared
size, and platform metadata sidecars are forbidden.

The first schema permits regular files, directories, and relative symlinks.
A symlink target must normalize inside `payload/`, may traverse only declared
directories, and may not participate in a cycle. Framework compatibility
symlinks are therefore representable without permitting extraction escapes.
Archive extraction occurs only through this validator into a new private
temporary directory; a generic `tar -x` or `Expand-Archive` into the final
store is not authoritative installation. The schema and trust policy set
finite archive-byte, member-count, per-file, symlink-depth, and total expanded-
byte limits. Those limits are checked from archive metadata before allocation
and again against bytes actually written, so compression or sparse-file bombs
cannot turn signature verification into unbounded extraction.

### Manifest

`ibex/portable-engine-manifest/1` is an RFC 8785 JCS object over I-JSON. Its
top-level exact field set is:

```text
schema, artifactId, artifactKind, target, profile, source, build,
interface, entries, runtimeComponent
```

`schema` is exactly `ibex/portable-engine-manifest/1`; `artifactKind` is exactly
`hermes` in v1. Every object at every depth rejects unknown or duplicate
fields. Strings are valid Unicode scalar values, integers are non-negative
I-JSON safe integers, booleans are JSON booleans, and semantic object digests
use `sha256-` plus 43-character unpadded base64url. Raw file, source-authority,
and PE image digests use `sha256-` plus exactly 64 lowercase hexadecimal
digits. No field accepts both encodings.

The nested exact field sets are:

- `target`: `triple, structuralFeatures`. `structuralFeatures` is a unique
  array sorted lexicographically by the UTF-8 bytes of its NFC strings.
- `profile`: `id, targetVariant, configuration, debugger,
  hermesBytecodeVersion, reviewedProfileIdentityDigest`.
- `source`: `artifact, sourceCommit, sourceRef, sourceVersion,
  patchStackDigest`. The complete reviewed profile remains in the declared
  receipt; `reviewedProfileIdentityDigest` commits to its independently
  reconstructed exact-field semantic projection.
- `build`: `repository, sourceRevision, sourceTreeDigest, sourceRef,
  publisherWorkflow, authorityDigests`. `authorityDigests` contains exact
  `path, digest` objects, is unique by normalized path, and is sorted by path.
  It covers every platform builder, installer, patch applier, manifest tool,
  and identity authority capable of affecting accepted output.
- `interface`: `abiContractDigest, requiredExportsDigest,
  forbiddenExportsDigest, headerSetDigest, hostTools, loadableComponents`.
  `hostTools` contains exact `role, path, digest, compatibilityDigest` objects
  sorted by `(role, path)`. `loadableComponents` contains two disjoint exact
  variants: payload rows have `role, path, digest, system` with `system:false`;
  platform rows have `role, name, system` with `system:true`. Platform rows are
  permitted only for a closed platform-system dependency name whose trust
  policy is defined outside the archive. Rows are sorted by
  `(system, role, path-or-name)`.
- `runtimeComponent` is a normalized payload-relative path string naming
  exactly one `loadableComponents` row whose role is `runtime` and whose
  `system` value is false.

The semantic digest inputs named by those fields are themselves closed JCS
documents, not implementation-defined strings:

- `sourceTreeDigest` is the domain-separated digest of
  `ibex/portable-engine-source-tree-identity/1`, whose exact fields are
  `schema, repository, sourceRevision, sourceRef, gitObjectFormat,
  sourceRevisionObjectType, sourceRevisionObjectContent, treeObjectId,
  treeObjectType, treeObjectContent`. Each `*ObjectContent` value binds a fixed
  payload path, raw digest, size, and the exact
  `raw-uncompressed-git-object-content` encoding. The raw commit and tree
  contents therefore travel inside the package rather than depending on
  network access or an incidental local `.git` object store.
  `sourceRevisionObjectType` and `treeObjectType` are exactly `commit` and
  `tree`; `gitObjectFormat` is `sha1` or `sha256` and determines the required
  40- or 64-hex width of both IDs. Verification hashes the supplied/fetched Git
  objects with their type-and-length prefixes and proves that the commit's
  single `tree` header names the declared tree object. Merely presenting two
  well-shaped IDs is insufficient. The external admitted-target policy pins
  the current GitHub repository to `sha1`; a coherent rewrite of the whole
  object graph to `sha256` is not admission. Its domain is
  `ibex.portable-engine-source-tree-identity.v1`.
- `reviewedProfileIdentityDigest` is the domain-separated digest of
  `ibex/portable-engine-reviewed-profile-identity/1`, whose exact outer fields
  are `schema, profileId, targetVariant, targetTriple, originKind,
  receiptPath, receiptDigest, reviewedProfileIdentity`. `receiptPath` names an
  exact regular `profile-receipt` payload member and `receiptDigest` binds its
  raw bytes. Verification strict-parses the schema-2 receipt, checks its exact
  target-specific field sets and runtime artifact binding, and derives the
  other outer fields plus `reviewedProfileIdentity` from that receipt rather
  than trusting a copied projection. Its three disjoint variants import the
  source-cache, Windows source-build, or Android Maven identity already
  enforced by receipt schema 2; the origin discriminator and identity shape
  must agree. For source-built Hermes the source commit is exactly 40
  lowercase hexadecimal digits, `sourceRef` is exactly
  `<sourceVersion>-stable`, and the source-cache key is reconstructed from the
  commit plus the complete patch/build/identity authority digests rather than
  trusted as an opaque receipt string. Its domain is
  `ibex.portable-engine-reviewed-profile-identity.v1`.
- `requiredExportsDigest` and `forbiddenExportsDigest` each bind one
  `ibex/portable-engine-export-set/1` document with exact fields `schema, mode,
  targetTriple, extractor, components, symbolNameSemantics, matchers`.
  `components` is a strictly sorted exact set of payload paths and raw digests,
  equal to the complete non-system `loadableComponents` set; each row must bind
  a regular manifest component before extraction. The
  extractor is one of the Mach-O external-defined nlist, ELF defined
  global/weak dynsym, or PE export-name table contracts. Symbol names are
  valid UTF-8 compared as exact bytes with no normalization. A matcher is only
  exact equality or a case-sensitive contiguous-byte `contains` check;
  regular expressions, demangling, locale folding, and tool-rendered lines are
  not inputs. Golden observations carry each parsed symbol name as separate
  base64-encoded bytes, preserving the no-normalization comparison contract.
  Every
  required matcher must match at least one extracted name and every forbidden
  matcher must match none. Matchers are unique and sorted by `(kind, value)`.
  Their domains are respectively `ibex.portable-engine-required-exports.v1`
  and `ibex.portable-engine-forbidden-exports.v1`.
- `headerSetDigest` binds `ibex/portable-engine-header-set/1`, with exact
  fields `schema, targetTriple, includeRoots, headers`. Include roots and
  `{path, digest, size}` header rows are strictly sorted and unique; the header
  rows must equal the complete regular `header` membership in the manifest.
  Its domain is `ibex.portable-engine-header-set.v1`.
- `abiContractDigest` binds `ibex/portable-engine-abi-contract/1`. The closed
  direct-JSI contract records target, C++ standard, compiler and
  standard-library ABI families, exception and RTTI modes, pointer width,
  endianness, allocation boundary, sorted contract features, and the three
  header/export digests above. Phase 0 accepts only the exact current macOS
  arm64 direct-JSI dimensions. The proposed Windows versioned C table is not a
  v1 variant until its spike freezes a version, getter symbol, calling
  convention, table layout/size, function-set digest, and ownership contract.
  Its domain is
  `ibex.portable-engine-abi-contract.v1`.
- Each host-tool `compatibilityDigest` binds one
  `ibex/portable-engine-host-tool-compatibility/1` document. It names the exact
  tool path/bytes, actual host triple, binary format/machine, and complete
  transitive host dependency closure. Its reviewed execution contract replaces
  rather than inherits the environment, supplies empty stdin, fixes argv0,
  uses a fresh private directory per invocation, and bounds time, stdout,
  stderr, and output bytes. Every fixture is an exact regular
  `compatibility-fixture` manifest member with independently unique payload and
  staged workspace paths, so two fixtures cannot overwrite one staged file;
  golden and physical producer evidence use the checked-in
  `tests/fixtures/portable-engine/host-tools/smoke.js` bytes as their shared
  source rather than maintaining a second hand-encoded program;
  invocation evidence binds exit, stdout/stderr sizes and
  digests, complete outputs, and bytecode version plus source path/digest.
  There is exactly one behavior document per manifest host tool, and the
  updater and verifier iterate the complete sorted collection. Its domain is
  `ibex.portable-engine-host-tool-compatibility.v1`.

All seven documents reject unknown fields. Their golden vectors join each
digest back to the manifest before deriving the interface digest and portable
artifact ID, so changing an inner contract necessarily changes every
downstream identity.

The exact JCS bytes of these inputs are declared `metadata` payload entries,
so a consumer never has to recover a digest preimage from an opaque string.
The six singleton documents live at fixed paths under
`payload/META-INF/authority/`; host-tool documents live under
`payload/META-INF/authority/host-tools/<compatibilityDigest>.json`. That
namespace also contains the two raw Git contents under
`payload/META-INF/authority/source-tree/`, bound by the source-tree document.
The reserved namespace contains exactly the declared directories and one document
for every manifest host tool. Each entry's raw digest and size bind the JCS
bytes, while its semantic digest binds the parsed closed document. Missing,
additional, non-canonical, renamed, or byte-substituted authority inputs are
rejected before artifact-ID derivation or component use.

`entries` is unique and sorted by normalized path's UTF-8 bytes. Its members
are one of three disjoint exact-field variants:

```text
regular:   kind, role, path, digest, size, executable
directory: kind, role, path
symlink:   kind, role, path, target
```

`kind` is respectively `regular`, `directory`, or `symlink`; `executable` is a
boolean portable mode class, not an ambient numeric mode. Every payload path
named by `hostTools`, a non-system `loadableComponents` row, or
`runtimeComponent` must name one regular entry with the same digest. The
runtime component and every Windows non-system loadable component must be a
regular file: symlinks, junctions, and reparse points are forbidden at those
paths. Directories record no owner, group, timestamps, ACLs, or local file IDs.
Those attributes are intentionally outside portable identity.

For Windows, every non-system loadable component is co-located in the runtime
component's one package directory. Its loader basename is unique under Windows
case-insensitive, trailing-dot/space, and Unicode-equivalence rules, and is
disjoint from every permitted system dependency name. Two manifest paths may
never compete for one PE import name.

Phase 0 materializes these rules as checked-in closed JSON Schemas plus golden
canonicalization/digest vectors before any implementation is permitted to
accept a portable identity. This prose is not permission to improvise missing
field types or optional extensions.

The payload includes the existing profile-provenance receipt as a declared
entry. The manifest repeats security-critical profile fields so validation can
join them exactly; disagreement is fatal. V1 does not replace receipt schema
2 merely to add a back-reference that would create a digest cycle.

No identity-bearing payload byte may contain the final portable artifact ID:
the payload hashes feed the manifest and the manifest feeds that ID. Hermes may
export the pre-manifest reviewed-profile identity digest for an independent
cross-check, but embedding `artifactId` would create an impossible fixed point.

`artifactId` is:

```text
"sha256-" || base64url(
  SHA-256("ibex.portable-engine-manifest.v1\0" || canonical-manifest-without-artifactId)
)
```

The archive member is byte-for-byte the JCS serialization including
`artifactId`. Unknown fields, unknown roles, unknown schema versions,
non-canonical bytes or array ordering, duplicate entries, or a self-digest
mismatch fail closed.

### Transport and distribution provenance

The publisher constructs and validates the manifest before packaging, creates
the final archive containing only the manifest and payload, and then attests
that archive's digest through the reviewed workflow. It publishes the archive
and detached provenance bundle as two associated transport objects. The
installer MUST verify the bundle's signature, trusted workflow identity, and
exact archive subject digest before parsing or extracting attacker-controlled
archive members.

For v1, GitHub build provenance is the package-publisher authority;
Authenticode publisher identity and SmartScreen reputation are explicitly out
of scope and are not implied by that provenance. If a later Windows publisher
signs or timestamps PE files, its mandatory order is build, Authenticode
sign/timestamp, verify signer policy and final PE bytes, hash and construct the
manifest, archive, then create detached GitHub provenance. Signing any payload
after manifest construction invalidates the artifact.

After extraction, the installer also joins the manifest's repository,
workflow, source ref/revision, target, and artifact kind to the independently
verified attestation claims. A correctly signed archive whose internal
manifest names a different build authority is rejected; neither side may
self-assert the other's binding.

The installer retains the verified attestation bundle, archive digest,
verification policy identity, signer workflow/ref/source revision, and
portable artifact ID in a canonical installation receipt. The receipt is not
trusted because it says `verified`; later consumers either reverify the
retained signed bundle or rely on a shard-provenance statement whose trusted
job independently performed that verification.

V1 retains exactly one Sigstore bundle JSON document with media type
`application/vnd.dev.sigstore.bundle.v0.3+json`. The stored file must be UTF-8
strict I-JSON with no duplicate keys or trailing second document.
`provenanceBundleDigest` is lowercase hexadecimal SHA-256 over the entire file
exactly as stored, including insignificant JSON whitespace and a final newline
if present. There is no JCS or newline normalization. Verification parses
those same retained bytes and validates their contained signature and claims;
re-serializing an equivalent JSON value produces different retained bytes and
a different digest. The checked trust policy freezes this byte projection and
media type, caps the stored bundle at 16 MiB, and requires offline signature,
subject, workflow/ref, and claim reverification before acceptance. The current
golden bundle is deliberately a **byte-projection-only** fixture with empty
verification material; it is not provenance-valid and grants no authority.
`portableArtifactAcceptanceEnabled` remains exactly false until a real
offline-verifiable bundle corpus and verifier exist.

The v1 installation receipt has exact fields `schema, artifactId,
manifestDigest, archiveDigest, provenanceBundleDigest,
verificationPolicyDigest, repository, publisherWorkflow, sourceRef,
sourceRevision, runnerClass`. Its schema is exactly
`ibex/portable-engine-installation-receipt/1`. The four digest fields use their
declared encoding from the manifest rules; all authority strings must equal
independently verified attestation claims. Time, local path, downloader,
release name, and mirror URL are deliberately absent. Unknown fields and a
receipt whose retained bundle does not reverify fail closed.

A checksum sidecar may diagnose corruption but supplies no authority. A source
build performed locally can create a byte-valid manifest, but remains
non-authoritative unless an admitted publisher signs its transport or a future
policy explicitly admits locally witnessed builds.

### Content-addressed installation

After provenance, schema, exact-membership, digest, export, receipt, target,
and profile validation, the installer atomically publishes the payload under:

```text
target/hermes-artifacts/<artifactId>/payload/
target/hermes-artifacts/<artifactId>/META-INF/portable-engine-manifest.json
target/hermes-artifacts/<artifactId>/LOCAL/transport/<archiveDigest>/
```

The `LOCAL/transport/<archiveDigest>/` record contains the detached verified
bundle and canonical installation receipt. `LOCAL/` is explicitly outside the
portable artifact identity: two admitted archive encodings may materialize the
same manifest and payload while retaining different transport digests and
bundles. An authoritative consumer selects one complete, policy-valid local
transport record and re-verifies its binding to the portable artifact before
use.

The path is checkout-local for the default developer workflow. A shared cache
may be used as a download source, but authoritative commands materialize or
revalidate the checkout-local store and never inherit a path from another
worktree. A convenience selector such as `target/hermes-artifacts/current`
may exist, but selectors and paths never enter semantic identity.

The store is not part of an evaluated application's virtual namespace. Armed
Host construction installs an unconditional lexical and retained-object fence
that denies evaluated JavaScript every write, truncate, rename, unlink, link,
writable-map, metadata-mutation, and directory-creation route into the store,
regardless of authored capability policy. The conformance suite proves that
fence adversarially. Transient mutation by a different malicious same-user
native process remains outside v1's threat model; a design that admits such a
process needs immutable storage rather than wider claims about two snapshots.

Publication sets the narrowest practical read/execute modes and writes a
durable completion marker last. Encountering an existing artifact ID is
success only when every identity-bearing manifest and payload byte revalidates
exactly and at least one selected local transport record independently
revalidates under current policy. Additional admitted transport records may be
published atomically without changing portable identity. Partial, writable,
redirected, identity-colliding, or provenance-confused stores are rejected and
rebuilt in a new location.

Authoritative build consumption occurs only in the fresh runner and job-owned
store described by the threat model. `build.rs` records the digests of every
header set, link input, host tool, runtime component, and non-system loadable
dependency it selects; a post-link verifier binds that consumption record to
every final engine-using PE or Mach-O executable and repeats payload validation
before conformance begins. A changed input fails even if a same-named path
still exists. This is a build-integrity check inside the trusted same-user job,
not a claim that Cargo can retain file handles across arbitrary compilers and
linkers in the presence of a malicious sibling process.

For an authoritative Cargo build, `build.rs` accepts an artifact ID or a
validated store root, selects the exact declared runtime/link/header
components, revalidates them, and embeds the canonical manifest plus
installation-provenance binding. Arbitrary `HERMES_LIB_DIR`, receipt, or DLL
paths remain useful for ordinary development but cannot set
`IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE=1` or emit promotion evidence unless
they resolve inside a successfully revalidated store.

The normal `run-manual-repl.sh` and conformance entry points resolve and, when
needed, install the reviewed package in the current checkout. A user should not
need `/path/to/another-worktree/target/hermes-*` to run the reviewed engine.

## Runtime identity split

### Portable identity

The runtime exposes a closed `PortableEngineArtifactIdentity` with exact fields
`schema, artifactId, artifactKind, target, profile, runtimeComponentDigest,
reviewedProfileIdentityDigest, interfaceContractDigest`. Its schema is exactly
`ibex/portable-engine-artifact-identity/1`; `target` has exact fields `triple,
structuralFeatures`; and `profile` has exact fields `id, targetVariant,
configuration, debugger, hermesBytecodeVersion`. Every value is projected from
and rejoined to the validated manifest. It never trusts a second hand-authored
copy of those fields. `interfaceContractDigest` is the tagged semantic digest
of the manifest's complete exact-field `interface` object, not merely the ABI
subfield.

No absolute path, device, inode, volume, file ID, cache key, archive filename,
runner ID, or install timestamp appears in this object.

### Mapped instance identity

`MappedEngineInstanceIdentity` has exact fields `schema, portable,
canonicalLocalRuntimePath, localObject, mappingProof, before, after,
processArchitecture, observationDigest`. Its schema is exactly
`ibex/mapped-engine-instance-identity/1`; `portable` is the complete closed
portable identity; `localObject` has exact fields `platform, volume, file`;
`mappingProof` has exact fields `class, platformObservation`; and `before` and
`after` each have exact fields `size, digest, object`. `platformObservation` is
a closed schema-discriminated union for macOS, Linux, and Windows rather than
an open JSON escape hatch. Phase 0's schemas fix each variant's exact fields,
types, and digest projection before any report consumes it.

This object is per-run evidence. It is never compared for equality across
runners and is never copied into a target advertisement.

At startup, Ibex obtains the module containing `makeHermesRuntime`, derives the
kernel-backed object for that mapped region, opens the manifest's runtime
component without following a final link, compares object identities, hashes
the pinned descriptor, validates the embedded portable manifest, and retains
the expected instance. Post-phase checks repeat the mapping and pinned-file
observations. Any change fails the shard and contaminates the runner when LLP
0032 requires it.

The engine cannot establish this proof merely by returning an identity. Hermes
may export the pre-manifest reviewed-profile identity digest as a useful
cross-check, but it MUST NOT embed or return the final portable artifact ID
from identity-bearing payload bytes. The Ibex-side
mapping-to-file-to-manifest join remains authoritative.

### Reports and advertisements

The next conformance-report and target-advertisement schema revisions replace
their semantic `engine` value with the portable identity. Execution artifacts
and shard manifests additionally retain mapped-instance identities before and
after engine-using work.

Production startup accepts an advertisement only when its portable identity
equals the independently reconstructed portable identity of the locally mapped
engine. It separately requires the local mapped-instance proof to pass. Thus an
advertisement earned on CI can authorize the same authenticated package in a
developer checkout without authorizing a merely same-named local library.

There is no compatibility coercion from the old combined identity. Old reports
must be regenerated under the new schema. Because the full-profile
advertisement set is currently empty, this migration grants no previously
unavailable target.

## Cross-runner conformance authority

Portable engine equality removes one blocker; it does not replace LLP 0032's
suite and shard rules.

V1 keeps promotion-authoritative execution under LLP 0032's one trusted
same-runner supervisor. Cross-runner shards are diagnostic only. Portable
identity does not launder them into authority, and cross-runner retry or
resumption is explicitly unsupported by this RFC. Enabling either requires a
follow-up accepted amendment with measured diagnostic results.

That amendment MUST preserve trusted assignment by construction. A dedicated
coordinator job, with a signer identity and protected environment unavailable
to shard jobs, independently reconstructs the suite plan and expected
membership from the reviewed source. It issues one canonical suite-lineage
descriptor and one exact shard-assignment descriptor per expected job. The
suite descriptor binds stable lineage ID, suite-plan digest, source
revision/tree, target/features, portable artifact ID, expected shard IDs,
expected command/fixture membership, coordinator workflow identity, and
coordinator run identity. Each assignment binds that suite descriptor, one
shard ID and exact membership, authority class, assigned shard-workflow
identity, and a coordinator-allocated monotonically increasing shard-attempt
number. The suite descriptor and complete assignment set form one canonical
assignment bundle; detached coordinator provenance attests that bundle's
digest. Neither descriptor contains its own bundle or provenance digest. Shard
jobs verify the detached coordinator provenance and cannot mint, widen, or
relabel the assignments.

Diagnostic and authoritative shard workflows use distinct signer identities,
permissions, protected environments, and artifact namespaces. An
authoritative aggregate accepts only coordinator-issued authoritative
assignments naming the exact shard signer it observes. It independently
reconstructs the plan and expected membership instead of trusting the
self-carried suite descriptor or authority label. A valid signature from the
diagnostic workflow is therefore categorically inadmissible.

Attempt identities are not overloaded. `suiteLineageId` is stable for the
coordinator-issued plan; `workflowRunId` and `workflowRunAttempt` identify one
CI execution; `shardAttempt` is durably and monotonically allocated by the
coordinator; and `aggregateAttempt` identifies one deterministic selection.
Any future retry design must authenticate a coordinator-issued lineage edge
from a prior attempt and retain both records. Until a durable non-steerable
allocator and crash-recovery protocol exist, no output from an earlier
cross-runner attempt is reusable.

Every diagnostic shard emits a canonical bundle containing its coordinator
assignment bundle and detached coordinator provenance, retained engine
distribution-provenance material, pre/post mapped-instance proofs,
command-envelope records, declared outputs, source/tree/toolchain observations,
and its complete assigned fixture evidence. The shard independently reverifies
the coordinator provenance before execution; the aggregate repeats that
verification. Its digest graph is an acyclic closed contract:

```text
declared output bytes
  -> output digests in shard manifest
  -> shard-manifest digest (manifestDigest omitted from its projection)
  -> canonical shard-bundle digest (manifest plus exact outputs and upstream
     coordinator/engine provenance inputs; no shard provenance)
  -> detached shard OIDC provenance over the shard-bundle digest
```

Neither the shard manifest nor bundle contains its own bundle digest, its own
detached shard provenance, or a digest of bytes that contain that shard
provenance. Detached coordinator and engine provenance are already completed
upstream inputs and create no reverse edge. Checked-in schemas define every
projection and domain string with golden vectors. The aggregate consumes
bundles by verified digest, not artifact-service name or filesystem order, and
rejects missing, duplicate, unexpected, ambiguously selected, self-assigned,
or diagnostic inputs exactly as LLP 0032 requires.

## Platform mapping requirements

### macOS

The existing `PROC_PIDREGIONPATHINFO` observation for the address of
`makeHermesRuntime`, joined to a no-follow pinned file and exact portable
manifest, is the v1 mapping proof. The runner rechecks it after every
engine-using phase. The whole universal runtime file is the portable component;
the target architecture records which slice the process executes. The v1
macOS profile MUST declare no non-system loadable dependency other than that
runtime component. A package that adds one is unpromotable until every such
Mach-O image receives the same mapped-file join.

### Linux

The existing `/proc/self/maps` device/inode observation is admissible when the
selected mapping contains the factory address, names a declared runtime
component, and joins to the pinned file and portable manifest. Deleted,
anonymous, memfd, overlay-identity-confused, or multiply matching mappings are
refused pending a separately reviewed proof. The v1 Linux profile likewise
MUST declare no additional non-system loadable component; adding one requires
complete mapped-object closure rather than assuming a matching primary `.so`
authenticates its dependencies.

### Windows

The current Windows check reopens the loader-reported pathname after the DLL
is already mapped. It cannot prove that the current path still names the image
section supplying executing code, so it remains diagnostic.

Every final Windows PE that can use Hermes — CLI, test executables, app hosts,
and any future dynamic bridge — MUST contain no ordinary or delay import for
the manifest-selected runtime component and no transitive importer for it.
This is checked by walking the complete final PE import graph rather than by
matching the name `hermesvm.dll` or inferring from linker flags. A pre-main
import would map code before Ibex can authenticate or pin its file and
therefore fails the target regardless of later checks.

The first admissible Windows design MUST:

1. ensure the runtime component and every manifest-declared non-system
   dependency are absent from the process before Ibex's authenticated loader
   runs, rejecting same-name and same-file preloads;
2. create or open a job-owned private store namespace with reparse points
   forbidden, then retain no-delete-share handles for every path component so
   no ancestor can be renamed or replaced during namespace traversal;
3. open the runtime component and every non-system loadable dependency by its
   manifest-derived absolute path with handles that permit loader reads but
   deny write and delete sharing, and hash plus identify every locked handle
   against the manifest;
4. prove the package's closed PE dependency inventory before loading, including
   ordinary imports, delay imports, forwarded exports, API-set resolution, and
   the transitive closure. Every non-system import must resolve uniquely by
   loader-name equivalence to one pinned co-located manifest component; system
   imports must belong to the checked platform-system allowlist and resolve
   through KnownDLLs or the canonical System32 directory;
5. load only the pinned runtime path with restricted DLL-search semantics that
   admit the pinned package directory and system directory, but not the current
   directory, executable directory, ambient `PATH`, or user search directories;
6. resolve one versioned C ABI function-table getter and prove the getter plus
   every returned function pointer belongs to the returned runtime `HMODULE`;
7. enumerate the mapped module and its dependency closure, join each
   non-system `HMODULE` path and file ID back to its already pinned handle, and
   reject every undeclared, second, or unexpectedly preloaded module;
8. retain the namespace handles, denying file handles, runtime `HMODULE`, and
   non-system dependency module references until all normal and worklet
   runtimes are destroyed; and
9. re-hash/re-identify every pinned handle and re-enumerate the module closure
   after engine-using work, then release module references before file and
   namespace handles in the specified teardown order.

The Windows mapping argument is therefore not a pathname-reopen assertion.
Its required theorem is: all ancestor namespace objects are retained against
rename/reparse substitution, the final component and dependency file objects
are retained against write/delete substitution, `LoadLibraryExW` is restricted
to those paths, and the returned module closure is joined by file ID to those
same handles. A later pathname match alone proves nothing. The physical test
corpus must include ancestor-directory rename/replacement races and must fail
the design if Windows permits any namespace transition that breaks this
theorem; in that case a sealed private namespace or stronger reviewed OS
primitive is required before promotion.

The explicit function table, not delay imports, is the selected design. It owns
all Hermes crossings used by the normal runtime and worklet paths: runtime
creation/destruction, bytecode version and sanity checks, prepared/source/HBC
evaluation, root creation/clone/release/value conversion, job draining,
exception/result extraction, attribution hooks, crash-manager lifecycle, and
worklet runtime creation/destruction. Phase 0 first inventories the current C++
bridge and lands a physical feasibility spike proving that complete surface can
cross the versioned C table. No C++ factory, JSI object, crash-manager vtable,
delay import, or cross-CRT allocation/destruction symbol may remain in an
engine-using Ibex PE import graph.

The implementation must test preloading, executable-directory and `PATH`
decoys, file and ancestor-directory rename/replace races, in-place mutation
attempts, alternate dependency search injection, undeclared/preloaded
non-system dependencies, a second same-named DLL, premature namespace/file or
module closure, function-table/address substitution, and normal/worklet
lifetime teardown. A portable package does not authorize Windows until every
engine-using final PE audit and those tests pass on the physical target.

## Implementation program

### Phase 0 — freeze authority schemas

- add the manifest, installation-receipt, portable-identity, mapped-instance,
  and shard-provenance schemas;
- add canonical digest golden vectors and mutation tests;
- record the fixed publisher and runner trust policy;
- inventory every normal/worklet Hermes C++ crossing and prove a versioned C
  function-table feasibility spike on Windows; and
- keep reports and advertisements unchanged and empty.

Implementation checkpoint (2026-07-19): the checked-in closed schemas,
trust policy, and valid/invalid vectors now freeze the outer manifest,
installation receipt, portable and mapped identities, coordinator assignment
chain, and diagnostic shard DAG. The policy admits only the `ccheever/ibex`
`hermes-artifacts.yml` publisher on `refs/heads/main` with a GitHub-hosted
runner, retains same-runner-only conformance authority, explicitly disables
portable artifact acceptance, and disables cross-runner assignment, diagnostic
transport, promotion authority, retry, and resumption. Its admitted-target
table contains exactly `aarch64-apple-darwin`; that row joins structural
features, the exact `source-patched/default/Release` debugger-off bytecode-v99
profile, SHA-1 source-object format, profile origin, the exact required and
forbidden export matcher policy, complete build-authority path membership
(for the currently existing Hermes build inputs), the required `bin/hermesc`
behavior proof, the runtime-only non-system loadable-component topology, export extractor,
mapping proof, dependency policy, receipt architecture, exact direct-JSI ABI
dimensions, and the hermetic host-tool execution contract. Unknown triples
have no default family. The HBC-v99 value is the version physically reported
by both the pinned Release
runtime and its bundled `hermesc`; the producer must rejoin those observations
rather than treating the checked policy value as evidence.
The policy also fixes finite archive and detached-bundle limits, the versioned
payload-path equivalence policy, symlink containment rules, and the empirically
observed macOS Release runtime's Apple system dependency set.

The inner vectors now verify Git commit-to-tree object identity, derive the
reviewed profile projection and producer-shaped source/cache identity from
exact schema-2 receipt bytes, bind externally reviewed export policies to every
non-system loadable component and exact observed symbol-name bytes, carry
host-tool fixtures as exact payload members with collision-free staging, and
iterate the externally required complete host-tool behavior document set. The
Windows C-table ABI variant remains deliberately absent.

The golden vectors freeze these semantic digest purposes and projections:

| Purpose | Domain | Projection |
|---|---|---|
| Source-tree identity | `ibex.portable-engine-source-tree-identity.v1` | complete source-tree identity document |
| Reviewed profile identity | `ibex.portable-engine-reviewed-profile-identity.v1` | complete reviewed-profile identity document |
| Required exports | `ibex.portable-engine-required-exports.v1` | complete required export-set document |
| Forbidden exports | `ibex.portable-engine-forbidden-exports.v1` | complete forbidden export-set document |
| Header set | `ibex.portable-engine-header-set.v1` | complete header-set document |
| ABI contract | `ibex.portable-engine-abi-contract.v1` | complete ABI-contract document |
| Host-tool compatibility | `ibex.portable-engine-host-tool-compatibility.v1` | one complete host-tool behavior document |
| Portable artifact ID | `ibex.portable-engine-manifest.v1` | manifest without `artifactId` |
| Complete manifest digest | `ibex.portable-engine-manifest-digest.v1` | complete manifest |
| Trust-policy digest | `ibex.portable-engine-provenance-trust-policy.v1` | complete checked policy |
| Interface-contract digest | `ibex.portable-engine-interface.v1` | complete manifest `interface` object |
| Mapped observation digest | `ibex.mapped-engine-instance-identity.v1` | mapped identity without `observationDigest` |
| Suite-descriptor digest | `ibex.portable-engine-suite-lineage.v1` | complete suite descriptor |
| Shard-assignment digest | `ibex.portable-engine-shard-assignment.v1` | complete assignment descriptor |
| Assignment-bundle digest | `ibex.portable-engine-assignment-bundle.v1` | complete assignment bundle |
| Diagnostic-manifest digest | `ibex.portable-engine-diagnostic-shard-manifest.v1` | shard manifest without `manifestDigest` |
| Diagnostic-bundle digest | `ibex.portable-engine-diagnostic-shard-bundle.v1` | complete diagnostic bundle |

The checked policy additionally selects one raw Sigstore bundle v0.3 JSON file
and lowercase-hex SHA-256 of its exact stored bytes for
`provenanceBundleDigest`; the vectors prove that whitespace normalization
changes that digest. This is only a byte-projection vector, not a valid
signature/claim vector, and portable acceptance remains killed.

This checkpoint intentionally consumes no new authority and does not complete
Phase 0. The Windows function-table inventory/feasibility spike and physical
Linux and Windows system-dependency allowlist validation remain open, and this
Draft has not completed its author-approved review. No installer or runtime is
yet permitted to accept these documents as promotion authority. The golden-
vector updater is not an artifact producer; Phase 1 must add the real manifest
packager to the publisher workflow and extend `buildAuthorityPaths` to its
complete code, schema, dependency-lock, and identity-authority closure before
any physical package can be admitted. Reports and advertisements therefore
stay unchanged and empty.

Exit: two paths containing the same validated payload derive the same portable
ID, every local/provenance field mutation is classified correctly, and no new
authority is consumed.

### Phase 1 — portable macOS package and checkout-local UX

- emit the manifest from the reviewed Hermes artifact workflow;
- publish detached distribution provenance for the closed archive and retain
  its verified local transport record;
- implement safe exact-membership extraction and the checkout-local store;
- make `build.rs`, conformance, and the manual REPL consume the verified store;
- emit the exact build-consumption record, bind it to every final engine-using
  executable with the post-link verifier, and protect the store from every
  evaluated-JavaScript mutation route; and
- retain the existing local mapped-object proof.

Exit: a clean checkout can install and run the reviewed Release engine without
another worktree, and archive/manifest/path/profile tampering fails before
linking or execution.

### Phase 2 — split runtime and publication identity

- expose portable and mapped-instance identities in Rust/C++ and JavaScript
  validators;
- bind all engine-using evidence to both layers;
- revise report, attestation, and advertisement schemas;
- update Host startup to compare the portable advertisement and independently
  verify its local mapping; and
- regenerate complete macOS evidence under the new schema.

Exit: reports and advertisements contain no host-local values, while every
accepted local run still proves its exact mapped file.

### Phase 3 — authenticated diagnostic shard transport

- emit signed diagnostic shard bundles on separate hosted runners;
- implement exact diagnostic aggregate verification, coordinator-assignment
  simulation, digest-DAG validation, and adversarial substitution tests;
- compare uninterrupted and cross-runner diagnostic semantic reports; and
- publish measured results for a separately reviewed LLP 0032 amendment.

Promotion-facing cross-runner authority, retries, and resumption remain
disabled. Enabling any of them requires the coordinator/signer/attempt design
above in an accepted amendment and a separate reviewed switch; green
diagnostics do not enable it.

### Phase 4 — Windows mapped-image proof

- remove eager engine loading from the authoritative Windows binary;
- add the versioned Hermes C ABI function table and a final-PE negative import
  audit;
- implement the locked-namespace, closed-dependency authenticated loader;
- run the physical race/substitution corpus;
- emit the same portable and local identity layers; and
- rerun the complete Windows target report.

Exit: Windows becomes independently eligible for its own complete report and
LLP 0021 advertisement gate. Cross-runner authority remains disabled pending
the separate accepted amendment; macOS evidence never substitutes for Windows
evidence.

## Acceptance criteria

This RFC's implementation is complete only when tests prove all of the
following:

- archive substitution, mirror substitution, checksum substitution, signer,
  repository, workflow, ref, revision, subject, and runner-class confusion are
  rejected;
- extraction rejects traversal, absolute paths, target-filesystem name
  collisions, reserved/alternate-stream names, undeclared files, missing
  files, hard links, special files, escaping or cyclic symlinks, resource-limit
  violations, size/digest drift, and partial publication;
- profile receipt, target, features, debugger state, source/patch/build
  authorities, exports, headers, tools, bytecode version, runtime component,
  and manifest self-digest join exactly;
- the same package under different safe local paths has one portable identity
  and different mapped-instance identities;
- the same runtime binary inside a different target/profile/interface package
  does not compare equal;
- replacement or mutation visible at any pre/post engine checkpoint invalidates
  the local proof, every evaluated-JavaScript attempt to mutate the store is
  denied, and transient hostile same-user native mutation is not claimed
  detectable without an immutable-store amendment;
- stale or substituted headers, link inputs, host tools, runtime dependencies,
  build-consumption records, or final engine-using executables fail the
  post-link binding before conformance begins;
- target reports and advertisements contain no absolute path or host-local
  object identity;
- Host startup rejects a valid advertisement paired with an unverified local
  mapping, and rejects a valid local mapping paired with another artifact's
  advertisement;
- the diagnostic shard verifier rejects signed bundles from another run, plan,
  source tree, target, artifact, shard, attempt, assignment, authority class,
  or unexpected runner, while every promotion aggregate rejects all diagnostic
  bundles;
- shard digests follow the output -> self-excluding manifest -> bundle ->
  detached-provenance DAG, and a bundle cannot carry or authenticate its own
  digest recursively;
- missing, duplicate, stale, corrupted, diagnostic, timed-out, contaminated,
  or ambiguously selected shards fail the aggregate;
- a clean current checkout can materialize its own reviewed engine and run the
  manual REPL/conformance entry points without an external worktree path; and
- every engine-using Windows PE has no ordinary, delay, or transitive Hermes
  import; its ordinary/delay/forwarded/API-set/transitive dependency inventory
  resolves uniquely; and it passes the preloaded-module,
  executable-directory/`PATH` decoy, file/ancestor-path replacement, in-place
  mutation, closed-dependency/search injection, second-module,
  namespace/file/module-lifetime, function-table/address, and worklet teardown
  corpus before any Windows evidence becomes promotion-authoritative.

## Kill rules

Do not enable portable report identity or cross-runner authority if:

- a manifest does not describe exact package membership;
- an installer trusts a release location, checksum, cache, or self-asserted
  receipt without independently verified publisher provenance;
- authoritative commands can select an arbitrary engine outside the verified
  store;
- local mapping proof is replaced by an engine-reported digest;
- a payload embeds the final portable artifact ID or any authority schema has
  a cyclic digest projection;
- shard provenance cannot distinguish trusted authoritative jobs from
  diagnostics or another workflow run;
- a shard self-assigns its authority, membership, or attempt instead of
  carrying a coordinator-issued assignment;
- Windows loads an unpinned non-system dependency, retains only a pathname
  observation, or releases a module reference before runtime teardown;
- any platform cannot join mapped code to the portable runtime component; or
- schema migration would grandfather an old report or advertise an incomplete
  target.

The permitted responses are to fix the proof, keep execution same-runner, or
keep the target unadvertised.

## Open questions

1. Should the first publisher require deterministic transport archives, even
   though archive digests are deliberately distinct from portable artifact
   identity?
2. The ABI contract now binds compiler and standard-library ABI families. Must
   it also bind exact compiler and SDK build identities for every platform?
3. Should a universal macOS runtime use one whole-file component identity or a
   second Mach-O slice identity for per-architecture diagnostics?
4. Which protected-branch and environment rules are required before
   conformance shard attestations from a release workflow are accepted as
   promotion authority?
5. Should a future offline/local promotion ceremony have a separate admitted
   signing root, or remain explicitly unsupported?
