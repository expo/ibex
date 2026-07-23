# Upstream public-repository provenance oracle (not Ibex)

`bundle.json` is the user-initiated SLSA v1 provenance attestation GitHub
holds for the `cli/cli` v2.93.0 release artifact
`gh_2.93.0_linux_amd64.tar.gz` (subject sha256
`02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0`), fetched
2026-07-22 with `gh attestation download gh_2.93.0_linux_amd64.tar.gz -R
cli/cli` (gh 2.93.0) and retained byte-exactly as the provenance-predicate
line of the returned JSONL.

- Size: 14,020 bytes
- SHA-256: `3335d20534e5118e8a716ceafea8dafb30b85fcd6ce7a87bff8a0ade960da105`

This is the measured shape of a **public**-repository GitHub artifact
attestation: a public-good Fulcio leaf (issuer organization `sigstore.dev`)
carrying an embedded signed certificate timestamp, exactly one `dsse` Rekor
entry with both an inclusion promise and an inclusion proof, and a present
but empty `timestampVerificationData`. Its certificate also carries the
deployment-environment claim extensions `1.3.6.1.4.1.57264.1.23`/`.24`
because cli/cli's workflow uses a deployment environment — Ibex's
`hermes-artifacts.yml` does not, so the exact-claims validator keeps its
closed 1..22 extension set until the first real Ibex public bundle is
measured.

The bundle exercises the public-good cryptographic path (chain, SCT, Rekor
inclusion, DSSE signature, certificate identity) offline. It is not an Ibex
artifact or trust authority, and its statement (21 subjects, cli/cli release
layout) is intentionally outside the single-subject Ibex statement profile.

cli/cli is distributed under the MIT license; the upstream license is
retained in `LICENSE.upstream`.
