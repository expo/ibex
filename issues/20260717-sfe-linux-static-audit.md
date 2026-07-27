# Linux static-dependency audit (libcurl disposition required)

**Status:** Open
**Impact:** 4
**Urgency:** 4
**Ease:** 5
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Linux static-dependency audit (libcurl disposition required)” shows the issue materially affects a supported product or engineering path; delay compounds an active rollout, reliability, or verification risk, while the ticket identifies a narrow, verified change or decision, with a direct reproduction or current implementation proof.
**Progress:** Implemented; first Ubuntu 22.04 CI execution pending
**Severity:** P2
**Systems:** Engine, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2a/§7 phase 1

`HERMES_LINK_STATIC` makes Hermes static but the binary still links
`stdc++`/`z`/`resolv`/`pthread`/`dl`, optional static ssl/crypto, and
libcurl **dynamically when present**. Audit what the Linux stub
actually links against the "no non-system dynamic libraries" rule; the
audit's required outputs include libcurl's disposition (vendored/static
vs classified into the recorded system baseline) and the minimum
glibc/CPU baseline recorded in the stub contract.

**Done when:** `ldd` CI check green under the stated rule; libcurl
disposition recorded; baseline in `StubContractV1`.

## Implementation evidence

- `scripts/audit-sfe-linux-deps.sh` audits the final ELF's target, system-only
  `DT_NEEDED` set, lack of RPATH/RUNPATH, `ldd` resolution, maximum GLIBC
  symbol version, and x86-64-v1 ISA floor. The Hermes artifact workflow runs
  it on `ubuntu-22.04` against `linux-glibc-2.35-x86-64-v1` and uploads the
  report.
- The release bundle and linker require full static Hermes, JSI, and
  Boost.Context; ICU is linked statically on the pinned builder.
- The compiled Linux profile advertises no network authority and compiles
  fetch/WebSocket unavailable. Its libcurl disposition is
  `absent-until-compiled-network-advertisement`; the normal source runtime is
  unchanged.
- A clean x86_64 Linux link and audit passed on the available Ubuntu 24.04
  builder. It measured GLIBC 2.39, x86-64 baseline, no RPATH, no libcurl, and
  only `ld-linux`, `libc`, `libgcc_s`, `libm`, `libresolv`, `libstdc++`, and
  `libz`. That host is intentionally not evidence for the release floor; the
  authoritative 2.35 check is the pinned Ubuntu 22.04 CI job.

The issue becomes complete when the first pinned workflow run is green; do not
infer a 2.35 claim from the 2.39 development host.
