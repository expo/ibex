# GitHub-private trusted-root provenance

`trusted_root.json` is the exact raw `trusted_root.json` target obtained through
GitHub's TUF repository at `https://tuf-repo.github.com` on 2026-07-20. The
verified metadata observed for that fetch was timestamp version 911, snapshot
version 74, and targets version 10.

- Size: 31,645 bytes
- SHA-256: `484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7`
- Media type: `application/vnd.dev.sigstore.trustedroot+json;version=0.1`
- Contents: six GitHub certificate authorities and six timestamp authorities;
  no Rekor or CT-log authorities

This file is independent trust material. It must never be refreshed from an
artifact mirror, bundle sibling, filename, or checksum supplied by a release.
Rotation requires a reviewed source update, exact metadata/digest recording,
and a fresh offline oracle run. There is no online fallback in the verifier.
