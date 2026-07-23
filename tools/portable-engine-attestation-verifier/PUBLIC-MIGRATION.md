# Public-flip migration runbook: attestation verifier and repo-identity pins

Status: **prep branch** (`prep/public-sigstore-verifier`). The verifier work
below is implemented and tested on this branch; everything in "After the
transfer" is deliberately NOT done yet because it asserts facts that only
become true once `ccheever/ibex` is transferred to the expo org and flipped
public. Fold this document into LLP 0035 when the branch lands.

## Done on this branch

- The verifier gains a second, parallel trust profile
  (`sigstore-public-good-rekor-v1`) selected exclusively by the expectations
  schema `ibex/github-public-artifact-attestation-expectations/1`:
  public-good Fulcio chain (issuer organization `sigstore.dev`), embedded
  SCT **required**, exactly one `dsse` Rekor entry with inclusion promise
  and proof, `timestampVerificationData` present but exactly empty, and the
  verified timestamp taken from Rekor integration (`Tlog`), not a TSA.
  Verification remains fully offline.
- The Sigstore public-good trusted root is pinned and embedded
  (`trust/sigstore-public-good/`, sha256
  `3c2cc7f3…bcac1a1`, 5,748 bytes) with the same rotation discipline as the
  GitHub-private root.
- A real public-repository oracle (`testdata/oracle/
  github-cli-v2.93.0-public-provenance/`) proves the complete cryptographic
  path offline. The GitHub-private profile is unchanged — its oracle output
  is byte-identical — and each profile rejects the other's bundles.

## Measured facts this profile rests on (re-verify against the first real Ibex public bundle)

1. Public-repo **workflow-initiated** provenance is signed by public-good
   Fulcio with an SCT and one Rekor `dsse` entry; the github-initiated
   *release* attestation stays on GitHub's private Fulcio + TSA. The
   verifier consumes only the former.
2. `timestampVerificationData` was empty on the measured bundle. If Ibex's
   first real bundle carries RFC3161 material too, widen
   `parsePublicBundleProfile` deliberately (and pin the new shape) rather
   than loosening exactness.
3. The measured cert carried deployment-environment claim extensions
   `1.3.6.1.4.1.57264.1.23`/`.24` **because cli/cli's workflow uses an
   `environment:`**. `hermes-artifacts.yml` does not, so
   `validateCertificateClaims` keeps its closed 1..22 extension set. If the
   first Ibex public cert carries `.23`/`.24` anyway, extend the closed set
   explicitly for the public profile only.

## After the transfer (`ccheever/ibex` → `expo/ibex`), in order

1. **Flip the repository identity pins** from `ccheever/ibex` to
   `expo/ibex` at every authoring site, then regenerate the generated
   artifacts (never hand-edit the canonical bundles):
   - `schemas/portable-engine-provenance-trust-policy-v1.json` (+ its
     `.schema.json` `const`), including `repositoryVisibility` → `public`
     and the expectations schema →
     `ibex/github-public-artifact-attestation-expectations/1`
   - `capsec/schema/policy-rules.schema.json` `const` +
     `capsec/registry/policy-rules.json`
   - `build_support/portable_engine_build_consumption.rs` (three sites)
   - `scripts/package-portable-hermes-macos.mjs` (authoring + the
     enginePublisher assertion)
   - `scripts/portable-engine-installer-core.mjs`
     (`EXPECTATIONS_SCHEMA` → public schema)
   - `.github/workflows` guard in the physical-promotion workflow
     (`"$GITHUB_REPOSITORY" == "ccheever/ibex"`)
   - test pins: `scripts/portable-engine-*.test.mjs`,
     `packages/ibex-devtools/src/scripts/
     portable-engine-provenance-schemas.test.mjs`,
     `capsec-surface-inventory.test.mjs`,
     `schemas/vectors/portable-engine-provenance-v1.valid.json`
   - LLP prose: 0005, 0013 §prebuilt mirrors, 0017 (push remotes), 0035
     (policy admits only `expo/ibex hermes-artifacts.yml`)
   - regenerate `capsec/examples/digest-bundle.canonical.json` and any other
     canonical example carrying the repository identity via their
     generators, then run the LLP 0032/ENG-24933 restamp chain (surface
     inventory authority digests → coverage-model review id →
     inherited-intrinsic digests → output-disposition catalogKeyDigest).
2. **Run `hermes-artifacts.yml` once on the public repo** and capture the
   produced attestation bundle for one artifact. Diff its shape against the
   measured facts above; adjust the public profile only with measured
   evidence, then vendor that bundle as the Ibex oracle (replacing the
   cli/cli oracle's role for statement validation: single subject, Ibex
   workflow layout) and pin the canonical verifier output.
3. **Switch consumers** (installer, packaging, promotion workflow) to the
   public expectations schema and delete or tombstone the private-profile
   expectations documents for Ibex artifacts. The private profile stays in
   the verifier for its oracle and for any retained pre-flip artifacts.
4. Re-run the full offline oracle suite plus one end-to-end
   `gh attestation verify`-equivalent check through the installer against a
   fresh public release before advertising LLP 0035 promotion.
