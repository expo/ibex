# LLP 0013 supply-chain containment demo

A first-party app (`app.js`) depends on a compromised package
(`node_modules/evil-pkg`) that tries to read `process.env.SECRET_TOKEN`.

    # Baseline — the dependency exfiltrates the secret:
    SECRET_TOKEN=hunter2 ibex run app.js
    #   app sees SECRET_TOKEN:  string
    #   evil-pkg result:        STOLEN:hunter2

    # With lockdown — the dependency is contained, the app is unaffected:
    rm -rf ~/Library/Caches/Ibex      # bundle cache is keyed by entry path
    SECRET_TOKEN=hunter2 ibex --lockdown run app.js
    #   app sees SECRET_TOKEN:  string
    #   evil-pkg result:        CONTAINED:TypeError

The cache clear matters only when toggling `--lockdown` on the *same* file: the
compartmentalized and plain bundles are cached under the same entry-path key.
