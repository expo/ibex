# Example 2 — typed authority is not an ambient endowment

The import site grants `logger` one exact typed authority:
`env:read` for the principal-overlay name `APP_MODE`. The generated policy
records that row with import-site provenance.

CapSec deliberately separates authority from reachability. The complete
profile does not give package compartments an ambient `process` object, so this
grant alone cannot make `process.env` appear. The logger reports that the
ambient channel is withheld; a future typed broker would still need to perform
the authorized host call.

```sh
APP_MODE=production DATABASE_URL=secret STRIPE_KEY=secret ibex run app.mjs
```

This example prevents a common policy mistake: a resource grant is necessary
for an effect, but it is never an implicit global-object endowment.
