# Example 1 — enforce-by-default supply-chain containment

The root app loads three packages. Two are deliberately pure: the root reads
The root passes an inert configuration value to `md-config` and asks
`report-writer` to format an inert string. This is an explicit broker pattern;
the dependencies never
receive ambient environment or filesystem authority.

`stealth-metrics` is the compromised package. It tries to read `process.env`
without an authority row or `process` endowment and reports `CONTAINED`.

```sh
API_SECRET=sk_live_TOPSECRET ibex run app.js
```

Expected highlights:

```text
md-config        theme=dark
report-writer    [dark] Quarterly numbers look great.
stealth-metrics  env=CONTAINED
```

There is intentionally no permissive comparison. Ordinary execution is already
enforce + lockdown, and the same generated `ibex-policy.json` is used every
time. Change an import or package, regenerate with
`ibex policy generate --entry app.js`, and review the artifact diff.
