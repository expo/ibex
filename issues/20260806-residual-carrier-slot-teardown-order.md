# Teardown order can strand a stale Hermes embedder carrier slot (LLP 0051 §C)

- **Status:** Open
- **Filed:** 2026-08-06 by the LLP 0051 lane (confirmed hazard; causal link
  to the live Exact symptom suspected but unproven — codex r1 finding 3).
- **Owner:** capsec / engine.
- **Date:** 2026-08-06

`~ScopedRuntimeSecurityContext` and the `ExactRuntimeDriveGuard` destructor
restore `g_vm_runtime` BEFORE the typed-stack restore performs its Hermes
sync (`exactSwapTypedPrincipalStackForRuntimeDrive` →
`exactSyncTypedPrincipalStackToHermes`, which no-ops when `g_vm_runtime` is
null). The outgoing VM's embedder-host constrained-principal slot can
therefore retain the extent's last non-empty value. Guarded entries clear it
on their next entry sync; any future guard-less entry would inherit it —
the same class LLP 0051 Design A closed for `ex_hermes_dispatch_event`.

Fix shape (LLP 0051 §C): a centralized two-runtime restoration helper —
clear/sync the outgoing VM's embedder slots while the outgoing runtime is
still selected, then switch `g_vm_runtime`, restore the incoming typed
stack, and sync the incoming VM. Apply to both guard and security-context
teardown, with a regression that reads the VM slot directly. Open question:
safety for off-owner worker scopes that deliberately leave `g_vm_runtime`
null (LLP 0051 open question 1). Required before the vulnerability class is
claimed closed; also wanted: an instrumented trace tying (or refuting) this
mechanism to the original Exact click denial.
