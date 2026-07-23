# Sigstore public-good trusted-root provenance

`trusted_root.json` is the Sigstore public-good instance trusted root as
resolved through GitHub CLI's embedded TUF client on 2026-07-22: the first
line of `gh attestation trusted-root` output from gh 2.93.0 (the second line
is GitHub's own private-profile root and is not retained here — that root is
pinned separately under `trust/github-private/`).

- Size: 5,748 bytes
- SHA-256: `3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1`
- Media type: `application/vnd.dev.sigstore.trustedroot+json;version=0.1`
- Contents: public-good Fulcio certificate authorities, Rekor transparency
  logs (`rekor.sigstore.dev` and `log2025-1.rekor.sigstore.dev`), two CT
  logs, and the Sigstore public-good timestamp authority

This file is independent trust material for the **public** attestation
profile that becomes reachable once the repository is public. It must never
be refreshed from an artifact mirror, bundle sibling, filename, or checksum
supplied by a release. Rotation requires a reviewed source update (for
example a fresh `gh attestation trusted-root` or direct TUF resolution
against `https://tuf-repo-cdn.sigstore.dev`), exact digest recording, and a
fresh offline oracle run. There is no online fallback in the verifier.
