# CapSec target advertisement for shipped stub contracts

**Status:** Open
**Impact:** 5
**Urgency:** 4
**Ease:** 3
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “CapSec target advertisement for shipped stub contracts” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the fix requires a few coordinated implementation and test surfaces, with specific cited code, progress, or acceptance criteria.
**Severity:** P2
**Systems:** Security, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §4/§7 phase 6, LLP 0021

Production arming refuses unadvertised targets, and the matrix
currently advertises **zero** verified exact targets (host tuple: 0
enforced / 7108 unsupported cells). This gate inherits the completion
of the LLP 0021 conformance program, which this program does not own —
this ticket tracks the dependency, contributes compiled-mode
conformance evidence where the stub profile needs its own rows, and
carries register item 4 (**blocked-on-decision**: whether v1 ships
before the first verified advertisement exists — the gate itself is
production posture and not negotiable).

**Done when:** the target matrix shows both shipped stub
contract/tuple profiles advertised from verified conformance reports,
or the register-4 decision explicitly re-sequences v1 against it.
