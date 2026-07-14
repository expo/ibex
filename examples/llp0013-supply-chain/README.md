# Typed CapSec supply-chain containment demo

A first-party app (`app.mjs`) depends on two packages. Its import-site
declaration grants `env-reader` typed `env:read` authority for `SECRET_TOKEN`;
`evil-pkg`, a compromised dependency that tries to read the same value, gets
an empty floor. `ibex-policy.json` is the generated, versioned, digest-bound
canonical policy—not a hand-authored string-policy file.

```sh
# Regenerate and verify the canonical artifact.
ibex policy generate --entry app.mjs
ibex policy check --entry app.mjs

# Ordinary execution is already enforce + lockdown; no security opt-in exists.
SECRET_TOKEN=hunter2 ibex run app.mjs
# env-reader: BLOCKED:TypeError
# evil-pkg:   CONTAINED:TypeError
```

The declaration gives `env-reader` host-boundary authority, but the complete
profile also withholds the ambient `process` global. Authority alone does not
reintroduce an ambient channel; a typed broker/endowment must be designed and
declared separately. This demo therefore proves containment, not ambient-env
compatibility.

Missing, malformed, stale, or tampered policy never selects a permissive
fallback. A missing policy means empty dependency authority, while an explicit
bad policy refuses before project code. The separate foreground diagnostic
workflow is `ibex capsec audit app.mjs`; it cannot be stored as production
posture or consume ambient endowment overrides.

The policy is committed like a lockfile. Each authority row carries provenance
that answers why it exists, and deleting an import then regenerating removes
the corresponding principal authority. Declarations inside `node_modules` are
not a grant channel.
