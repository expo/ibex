# Hermes patches 0010/0011 are missing the in-file classification header

**Filed:** 2026-07-26 (found during Exact LLP 0404 review; verified — 0009
and 0012 carry `# Class:` header blocks, 0010 and 0011 begin directly with
`diff --git`)

`patches/hermes/README.md` says each patch is classified in its header, and
the digest-keyed identity machinery treats the patch files as authoritative
bytes — but `0010-completion-record-discriminator.patch` and
`0011-structured-async-failure-provenance.patch` have no header comments at
all. Their README-table classifications exist, so this is governance drift,
not a semantic problem.

Fix: add the same `# LLP …` / `# Class:` / `# @ref` header block the other
patches carry. Note this changes the patch bytes and therefore
`ibex_hermes_patch_digest()` — land it as a deliberate digest-bumping commit
(artifact cache re-key), ideally batched with the next pin bump rather than
alone.
