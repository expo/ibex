# First real expo/ibex public attestation oracle

`bundle.json` is the SLSA v1 provenance attestation GitHub produced for the
first successful `hermes-artifacts.yml` run on the public `expo/ibex`
repository (run 30004214526, commit
`63181c76ca129c3becd85e570db454e1787c3633`, 2026-07-23). It attests the macOS
arm64 portable Hermes artifact
`hermes-portable-macos-arm64-release-…-63181c76….tar.gz` published to the
`hermes-portable-…-63181c76…` pre-release. Retained byte-exactly as the
`.sigstore.json` asset from that release.

- Bundle size: 10,939 bytes
- Bundle SHA-256: `daec71832c567fcca5e8e991acdb23250c6a548d2ca0fc866ace0bece89eada0`
- Signed subject: the 12,771,809-byte artifact, SHA-256
  `96617169e267c3626701ccc3f726965e79422ad9326b245310498769f89141fb`
  (verified equal to the real downloaded artifact bytes)

This is the authoritative measured shape of an **expo/ibex** public-good
attestation, and it differs from the earlier GitHub-CLI export oracle in three
ways that the public profile was widened to accept, each measured here rather
than assumed:

1. `verificationMaterial.timestampVerificationData` is `{"rfc3161Timestamps":
   []}` (present key, empty array) rather than `{}`. Both mean "no TSA
   material; the verified timestamp is Rekor-integrated."
2. The DSSE signature carries `keyid: ""` (empty) alongside `sig`. `keyid` is
   an optional DSSE field; the key is identified by the leaf certificate.
3. The public-good Fulcio leaf carries one extra claim extension, OID
   `1.3.6.1.4.1.57264.1.24`, a source-repository snapshot
   `repo:expo@12504344/ibex@1268046138:ref:refs/heads/main`. The verifier
   binds it to that derived value.

The full offline path was proven against the real 12 MB artifact with the
built verifier (chain to public-good Fulcio, embedded SCT, Rekor inclusion,
DSSE signature, certificate identity, and subject-digest join → canonical
`ibex/github-public-artifact-attestation-verification/1`, signer expo/ibex,
visibility public, Tlog timestamp). The artifact bytes are not vendored (12
MB); the oracle test reproduces the complete cryptographic path against the
bundle's own signed subject digest.

The artifact is the property of the Ibex project; the bundle is a genuine
Sigstore/GitHub attestation and a trust anchor only for its own subject.
