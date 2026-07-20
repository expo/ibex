# Upstream GitHub-private oracle (not Ibex)

These files are copied from the GitHub CLI v2.93.0 source tree at commit
`f96972ce1c11fdb8eaa556257fde962a363dffde`:

- `pkg/cmd/attestation/test/data/github_provenance_demo-0.0.12-py3-none-any-bundle.jsonl`
  becomes `bundle.json`: 4,885 bytes, SHA-256
  `4f8c096e38a0eee242574ab100d16701928605409225e59784a3636f742bb27e`.
- `pkg/cmd/attestation/test/data/github_provenance_demo-0.0.12-py3-none-any.whl`
  becomes the decoded content of `artifact.whl.base64`: 1,437 bytes, SHA-256
  `ae57936def59bc4c75edd3a837d89bcefc6d3a5e31d55a6fa7a71624f92c3c3b`.

Upstream: `https://github.com/cli/cli/tree/f96972ce1c11fdb8eaa556257fde962a363dffde/pkg/cmd/attestation/test/data`

GitHub CLI is distributed under the MIT License; the upstream notice is
retained in `LICENSE.upstream`.

`expectations.json` is Ibex test policy containing only the locally knowable
authority fields needed to exercise exact joins. Dynamic workflow name,
selected trigger, run ID, and attempt remain signed observations derived by the
verifier. This corpus belongs to `actions/attest-demo`; it is not an Ibex
artifact, publisher authorization, or release-acceptance fixture.
