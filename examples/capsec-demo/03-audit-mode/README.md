# Example 3 — explicit foreground audit

Audit is an ephemeral diagnostic command, not a policy mode that can be stored
or selected by `ibex run`. This root-only fixture reads a local file and checks
an environment name so the diagnostic has real operations to observe:

```sh
API_SECRET=sk_live_TOPSECRET ibex capsec audit app.js
```

There is no `ibex-policy.json` in this folder. Foreground audit uses its own
arming workflow, accepts no durable audit policy or ambient endowment override,
and exits nonzero if the diagnostic itself cannot run.
