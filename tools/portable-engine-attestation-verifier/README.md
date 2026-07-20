# Portable engine attestation verifier

This directory is a standalone phase-1 foundation for verifying one retained
GitHub-private artifact-attestation bundle entirely offline. It does **not**
enable Ibex artifact acceptance, install an engine, advertise a target cell, or
change any workflow or runtime policy. The positive corpus is an upstream
GitHub CLI fixture, not evidence about an Ibex publisher.

## Closed input profile

The executable requires three paths:

```text
portable-engine-attestation-verifier \
  --bundle retained.sigstore.json \
  --artifact artifact.tar.gz \
  --expectations expected-claims.json
```

It accepts only:

- one regular, non-symlink Sigstore v0.3 JSON bundle of at most 16 MiB;
- strict I-JSON (valid scalar Unicode, no duplicate object names, finite
  binary64 numbers, safe integers, one document, and at most 64 nested
  containers), with bounded container cardinality, member names, and number
  tokens;
- one leaf certificate, one DSSE signature, and exactly one RFC3161 signed
  timestamp;
- no Rekor field, no certificate-transparency material, and no SCT extension;
- one regular, nonempty artifact of at most 1 GiB whose SHA-256 digest is the
  sole signed subject digest; and
- one strict, closed expectations document of at most 64 KiB.

The expectations document supplies only locally knowable authority claims:
subject name, repository and numeric IDs, workflow path, source ref and exact
40-hex revision, the closed allowed-trigger set, runner environment, private
visibility, certificate SAN and issuer, build type, and builder ID. Workflow
display name, selected trigger, run ID, and attempt are signed observations,
not user-supplied trust inputs; the verifier derives them from the certificate,
checks their canonical forms, and requires the SLSA statement to agree.
Repository, workflow, dependency, invocation, SAN, and builder URIs join
exactly across those policy inputs, certificate claims, and statement.

The only trust root is
[`trust/github-private/trusted_root.json`](trust/github-private/trusted_root.json).
The verifier rechecks its exact 31,645-byte size and SHA-256 digest
`484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7`
before passing it to `sigstore-go`. Verification uses
`verify.WithSignedTimestamps(1)` and makes no network request.

Success writes one newline-terminated JCS JSON result. Failure writes no result.
That result is deliberately closed and carries the bundle, artifact,
expectations, and root digests plus the exact verified claims and TSA time.

## Build and test

The implementation uses the official `github.com/sigstore/sigstore-go` v1.2.2
source, pinned transitively by `go.mod` and `go.sum`; no downloaded verifier
binary is used. That release requires Go 1.25.8 or newer. The repository build
script intentionally pins Go 1.26.5 so compiler changes cannot silently change
the helper binary:

```sh
scripts/build-portable-engine-attestation-verifier.sh
```

Set `IBEX_ATTESTATION_GO` to an explicit Go 1.26.5 executable when `go` on
`PATH` is different. The first build may download checksum-pinned Go modules.
The resulting verifier performs no downloads, and all tests use checked-in
fixtures only. The official Sigstore dependency has a substantial transitive
graph; dependency review, vulnerability response, and compiler/toolchain
updates are therefore explicit maintenance work rather than ambient upgrades.

To run the module tests directly:

```sh
cd tools/portable-engine-attestation-verifier
GOTOOLCHAIN=local go test -count=1 ./...
```

## Oracle corpus

The positive oracle is copied from GitHub CLI v2.93.0 and exercises a real
GitHub-private, signed-timestamp-only bundle. Its artifact is stored as base64
only so this repository remains text-normalized. The negative public-good
oracle comes from sigstore-go v1.2.2 and proves that a Rekor-bearing public
profile is outside this verifier. Exact upstream commits, paths, hashes, and
licenses are recorded beside each fixture.

The legacy GitHub workflow build type in the positive fixture is accepted only
when the caller explicitly supplies that exact build type and legacy builder
ID. A separate statement-shape test follows the current
`actions/attest-build-provenance` v2.4.0 implementation pinned at
`e8998f949152b193b063cb0ec769d69d929409be`, which uses
`https://actions.github.io/buildtypes/workflow/v1`, a
`runner_environment` claim, and a job-workflow builder URI. That shape test is
synthetic and is not a signed Ibex corpus.

## Work required before enabling acceptance

As of 2026-07-20, the Ibex publishing workflow pins every invoked action by an
exact reviewed commit, including the attester named above. Before this
foundation can become release authority, a real private Ibex artifact/bundle
corpus must demonstrate the resulting claim layout and production must be
isolated from the credentialed publisher. The root rotation process and Go
dependency/toolchain review also need owners.

Only after those publisher inputs are closed should a separate integration
change connect this canonical result to package identity, installer/build
receipts, runtime acceptance, target advertisement, and conformance cells.
None of those consumers trusts this helper today.
