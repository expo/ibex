# LLP 0013/0014 supply-chain containment demo

A first-party app (`app.mjs`) depends on two packages. At its import sites it
grants `env-reader` ambient env access and grants `evil-pkg` (a compromised
dependency that tries to read `process.env.SECRET_TOKEN`) nothing. The policy
file is **generated from those import sites** (LLP 0014), never hand-edited.

    # Baseline — no lockdown: the compromised dependency exfiltrates:
    SECRET_TOKEN=hunter2 ibex run app.mjs
    #   evil-pkg   (granted nothing):     STOLEN:hunter2

    # Lockdown alone contains every package — including the legitimate one:
    SECRET_TOKEN=hunter2 ibex --lockdown run app.mjs
    #   env-reader (granted process:env): BLOCKED:TypeError
    #   evil-pkg   (granted nothing):     CONTAINED:TypeError

    # Generate the policy from the import sites, then run with it. The
    # granted package works again; the compromised one stays contained:
    ibex policy generate --entry app.mjs
    SECRET_TOKEN=hunter2 ibex --lockdown --policy ibex-policy.json run app.mjs
    #   env-reader (granted process:env): OK:string
    #   evil-pkg   (granted nothing):     CONTAINED:TypeError

    # CI drift gate — fails (with expansions called out) whenever the
    # import sites and the committed artifact disagree:
    ibex policy check --entry app.mjs

`ibex-policy.json` is committed like a lockfile: every grant carries
provenance (`"site": "app.mjs:5"`), so each entry answers "why is this
here". Delete the `env-reader` import and regenerate — its grant disappears
with the code that motivated it. Grant syntax inside `node_modules` is never
a grant channel; the generator strips it, ignores it, and reports it.

The compartmentalized and plain bundles are cached under distinct keys, so
you can toggle `--lockdown` on the same file freely without clearing the
cache.
