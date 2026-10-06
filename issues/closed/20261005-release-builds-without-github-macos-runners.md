# Release builds shouldn't depend on GitHub-hosted macOS runner capacity

**Status:** Closed (2026-10-06)
**Resolution:** Option 1. The macOS and iOS builder jobs now use the larger hosted runners (`macos-15-xlarge`, `macos-15-large`); a probe started both within seconds. Charlie: "the expo paid larger macos runners is probably right." Self-hosted runners and a relaxed publisher head check were not needed.
**Opened:** 2026-10-05 (Charlie: "maybe we should set up the process to not rely on github mac runners … i have some mac capacity of my own")
**Area:** `.github/workflows/hermes-vanilla-build.yml`, docs/hermes-vanilla-release.md

## What happened

The v3 Hermes release build (run `37359120807`) finished its Linux, Windows, and macOS
x86_64 jobs, then waited for `macos-15` runners behind an org-wide queue (expo/expo had
47 runs queued). The iOS jobs got runners after about 2 hours. The macOS arm64 job was
cancelled unassigned after 140 minutes, and a re-run of just that job succeeded. In the
v2 build the same jobs started within seconds. While a build waits, nothing may be pushed
to `main`, because the publisher only accepts a build of `main`'s current head.

## Options

1. **Larger GitHub-hosted macOS runners**, if the `expo` org has them (dedicated
   capacity). This is a one-line `runs-on` change that keeps hermetic, throwaway VMs. Check
   first. Querying runner groups needs `admin:org`.
2. **Self-hosted runners on Charlie's Macs**, done safely:
   - Run each job in an ephemeral macOS VM (Tart on the Studio, for example), not as a
     normal user on a fleet machine. Fleet machines run many agent sessions with full
     permissions, so a shared account is not a trustworthy build environment.
   - Register just-in-time, ephemeral runners in a runner group restricted to `expo/ibex`
     and to `hermes-vanilla-build.yml` only. The repo is public, so no
     `pull_request`-triggered workflow may ever schedule on them.
   - Keep GitHub-hosted runners as the fallback label.
   - Document the trust change. The attestation still binds the bytes to the publisher on
     `main`, but the build environment becomes Charlie's VM rather than GitHub's.
3. **Optional, later:** check reproducibility by building on both and comparing archive
   digests. Apple archives are already normalized with `libtool -D`, and Linux builds run
   in a digest-pinned container with a dated Debian snapshot.

Also worth considering: let the publisher verify a build of a recent `main` commit
rather than only the current head, so other work can land during a long build. That's a
trust-model change; decide it explicitly.

**Done when:** a release build's macOS jobs start within minutes regardless of org
queue load, and the trust model is documented.
