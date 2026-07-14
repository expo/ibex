# Example 4 — drift and tampering fail closed

The canonical `ibex-policy.json` is generated from `app.mjs` and checked like a
lockfile:

```sh
ibex policy check --entry app.mjs
ibex run app.mjs
```

`../run.sh 4` then copies the artifact to a temporary file, mutates one byte of
its digest, and passes it explicitly with `--policy`. Ibex refuses before the
application runs. The expected failure is asserted; if the tampered policy ever
runs, the demo script exits nonzero.

This replaces the retired first-party string-denial example. Rev2 production
policy is typed, generated, enforce-only, and digest-bound—there is no
hand-authored `{ mode, deny, packages }` escape hatch.
