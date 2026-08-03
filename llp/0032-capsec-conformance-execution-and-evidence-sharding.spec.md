# LLP 0032: CapSec Conformance Execution and Evidence Sharding

**Type:** Spec
**Status:** Accepted
**Systems:** Security, CI, Build, Runtime, Engine, Tooling
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-19
**Revised:** 2026-08-03
**Related:** LLP 0001; LLP 0005; LLP 0013; LLP 0021

## Summary

This document specifies bounded, observable, resumable execution for the CapSec
conformance suite and defines the conditions under which its work may be split
into shards.

The first implementation should preserve the existing authority model while
making failures cheaper to diagnose and retry:

1. every command receives an explicit deadline and process-tree cleanup;
2. the suite is divided into named, resumable phases on one authoritative
   runner;
3. parallel cross-runner shards may provide diagnostic feedback, but do not
   contribute promotion evidence; and
4. cross-runner authoritative aggregation remains prohibited until Ibex has a
   portable engine-identity and artifact-provenance contract.

This document governs execution mechanics. LLP 0021 continues to govern what
constitutes CapSec conformance, which evidence is authoritative, and whether a
target may be promoted.

Implementation status (2026-07-19): Stage 1 is in progress on the accepted
specification. The versioned plan lives at `capsec/conformance/suite-plan.json`;
the command supervisor, outcome/live-status artifacts, POSIX containment,
Windows kill-on-close Job Object wrapper, attestation reorder, and workflow
integration are implemented pending complete macOS, Linux, and Windows
verification. The pre-Stage-1 timing evidence and the explicit decision to
defer Stage 2 are recorded in
`capsec/conformance/stage1-timing-baseline.md`. No sharding work has begun.

Implementation checkpoint (2026-07-20): the plan declares a distinct
`portable-public-fixtures-` dynamic command class in the fixture-evidence
phase. The aarch64 macOS target admits at most eight such warm-cache reruns at
90 seconds each; Windows admits none in this checkpoint. The critical-path
calculation charges this class separately from the original public-fixture
batches and still fits the declared six-hour macOS outer bound. These commands
exist only for explicit LLP 0035 portable promotion and remain on the same
authoritative runner.

Implementation checkpoint (2026-07-25): retained arm64 evidence showed the
554-row native public batch crossing the original 300-second deadline and
being terminated after its 30-second cleanup grace, without an assertion
failure. Timeout policy version 2 raises the public-fixture class deadline to
390 seconds. The revised maximum critical paths, including declared setup and
cleanup/upload reserves, remain below the 375-minute outer target bounds.

Implementation checkpoint (2026-07-25): a second assertion-free native-batch
timeout occurred at 420.263 seconds (the 390-second deadline plus cleanup
grace) while unrelated work saturated eight host cores. Rather than extending
one monolithic evidence window again, Stage 3 now applies narrowly to this
cohort on the same authoritative runner and mapped engine. A SHA-256 partition
of the exact fixture ID assigns every native, host-ABI, and module-loader
recipe to one of two disjoint Cargo test commands; the runner's existing
cross-batch merge rejects missing, added, or duplicate membership. The current
Apple catalog partitions 554 rows as 282 and 272. Under the same contention
the shards completed in 116.98 and 100.98 seconds. Timeout policy version 3
therefore returns the common public-fixture deadline to 300 seconds and raises
the maximum public batch counts to nine on Apple and eight on Windows. Maximum
critical paths are 366 and 364 minutes respectively, including reserves, below
the unchanged 375-minute outer bounds.

Implementation checkpoint (2026-08-03): the reviewed public-surface catalog
now produces 11 Apple and 10 Windows command batches. Timeout policy version 4
raises the per-target batch ceilings to those exact counts. The Apple setup
that preceded the matrix completed in under 29 minutes in the failing CI
observation, so its conservative setup reserve narrows from 60 to 58 minutes;
the command deadlines and cleanup/upload reserve do not change. The resulting
maximum critical paths are 374 minutes on both Apple and Windows, leaving one
minute of outer-budget headroom for tests that exercise bounded policy
variants.

## Motivation

The current conformance workflow runs one job per target with a single
dominant runner step (`run-capsec-conformance.mjs`), bounded only by the job's
`timeout-minutes` (180 on macOS, 240 on Windows). Inside that step, the runner
executes preflight checks, engine attestation, recipe generation, adapter and
public fixture batches, product commands, a post-suite attestation, fixture
evidence, and final report construction in sequence via synchronous child
execution. No individual command has its own deadline, and two children
(recipe generation and report construction) run outside the observed-command
evidence path entirely. The macOS job additionally runs a second conformance
entry point (inherited-intrinsic alias conformance) after the main runner.

That shape has three operational costs:

- a hung child command consumes the remaining job timeout without identifying
  a precise bounded failure;
- when a late command fails or the job reaches its outer timeout, secured
  command logs and partial outputs survive as diagnostic uploads (whenever the
  runner is still alive), but they are lost as substrate for authoritative
  reuse — the entire suite must re-run; and
- the workflow cannot safely exploit parallel capacity without first defining
  which outputs may be combined and how their identities are proven.

More hardware can reduce the duration of compute-bound commands, but it cannot
make an unbounded command bounded, preserve completed work after a late failure,
or make evidence from different runners equivalent. Those are execution and
provenance problems.

## Scope

This specification covers:

- command deadlines and termination;
- live execution status and retained failure diagnostics;
- phase boundaries and resumability;
- diagnostic and authoritative shard classes;
- shard manifests and aggregate validation;
- CI behavior when a command times out, is canceled, or loses its runner; and
- the staged adoption path from the present monolithic runner.

It does not change:

- the CapSec capability model;
- the fixture vocabulary, registry, policy, or expected semantic results;
- the promotion rules in LLP 0021;
- whether broad test suites count as fixture evidence; or
- the target support matrix in LLP 0001.

## Terminology

**Command** is one invoked program together with its arguments, environment,
working directory, declared inputs, deadline, and expected outputs.

**Phase** is a named, ordered group of commands whose validated outputs may be
reused by a later attempt of the same conformance plan.

**Shard** is a subset of a conformance plan with an explicit identity and an
expected output set.

**Diagnostic shard** is parallel work intended to shorten feedback time. Its
result can identify a failure but cannot establish conformance or authorize
promotion.

**Authoritative shard** produces evidence eligible for the aggregate
conformance result, subject to every rule in this document and LLP 0021.

**Attempt** is one execution of a command, phase, or shard. Retrying creates a
new attempt; it never rewrites the identity or record of the old attempt.

**Suite-plan digest** (`suitePlanDigest`) commits to the complete intended
run: source identity, target, engine identity requirements, command graph,
expected shard membership, timeout policy, and all conformance inputs. It is
distinct from the existing fixture-level `planDigest` and the output-sweep
`sweepPlanDigest`; the three are never interchangeable, and manifests MUST use
the distinct field names. Throughout this document, "plan digest" means the
suite-plan digest.

**Canonical form.** Wherever this document requires a digest of a manifest or
record, the input is the canonical JSON serialization already used by the
CapSec evidence tooling, hashed with a domain-separated (tagged) digest whose
tag names the schema. A manifest's own digest field is excluded from its
digest input. Digests over unspecified serializations are not valid evidence.

## Authority boundary

LLP 0021 owns the definition of conformance and promotion authority. This
document owns execution and assembly mechanics. Where the two conflict, LLP
0021's evidence and promotion requirements prevail.

Splitting a suite does not broaden what counts as evidence. In particular:

- compiler, package, unit, integration, Android, and Hermes checks remain
  product prerequisites rather than substitutes for fixture evidence;
- logs and heartbeats are diagnostics, not semantic evidence;
- a diagnostic shard never becomes authoritative merely because it passed; and
- incomplete, timed-out, canceled, or mismatched work cannot be interpreted as
  an absent or unsupported target cell.

## Required execution model

### Command envelope

Every command MUST execute through a common command envelope. "Every command"
means every child process the suite spawns, including generators and report
construction that today run outside the observed-command path (recipe
generation and report generation via bare `execFileSync`), and every
additional conformance entry point a CI job invokes (such as the macOS
inherited-intrinsic alias conformance step). A child process with no envelope
record is a conformance failure, not an implementation detail.

Short-lived helper invocations (for example the runner's `git` metadata
queries) are the one permitted exception: they MAY run outside the envelope
only if they belong to a helper class explicitly enumerated in the plan,
produce no evidence output, and remain bounded by their phase's deadline.
Suite code MUST NOT spawn children outside the envelope and the enumerated
helper class, and that rule SHOULD be enforced by test or by construction.

The natural implementation seam is the existing secured observed-command
machinery (`capsec-command-evidence.mjs`), extended with deadlines and
process-tree cleanup, rather than a parallel mechanism. The existing
`scripts/with-timeout.sh` is not sufficient: descendants can escape its
process group, its macOS path depends on Homebrew `gtimeout`, it has no
Windows Job Object semantics, and it produces no evidence record.

The envelope MUST record at least:

- command identity and redacted invocation — command identity is a
  domain-separated digest of the closed command descriptor (executable,
  arguments, working directory, environment projection, declared inputs,
  deadline, and expected outputs) together with its plan, phase, and shard
  bindings, so a record cannot be replayed under a different plan or
  substituted for a different command; secret environment values are
  committed by digest while the displayed invocation stays redacted. This
  identity contract applies from Stage 1;
- attempt identity;
- start and finish timestamps;
- monotonic elapsed duration;
- configured deadline and grace period;
- exit status, signal, timeout, cancellation, or runner-loss classification;
- process-tree termination actions and their results;
- secure log identity and digest; and
- declared output identities and digests.

The envelope MUST update an atomic live-status record when a command starts,
periodically while it runs, and when it terminates. The status identifies the
phase, shard, command, attempt, elapsed duration, and deadline. A heartbeat is
for diagnosis only and MUST NOT extend the deadline. This requirement implies
asynchronous child supervision (or a supervising helper process); the current
single-threaded synchronous spawn cannot satisfy it. The live-status record
MUST be observable while CI is running — at minimum as periodic CI log lines,
with the status file itself uploaded on termination.

Runner-loss classification is necessarily external: a process on a lost
runner cannot record its own death, and a lost runner's status file may never
be uploaded. Where an observer outside the runner exists (a separate observer
job, or an aggregator reading a durable heartbeat transport), it MAY
synthesize a runner-loss record from a stopped heartbeat; that record is an
infrastructure classification with its own record class, never
command-produced evidence, and MUST NOT be accepted where command-produced
evidence is required. Where no external observer exists — the normal hosted-CI
case in Stages 1–2 — no synthesis is required: the absence of an expected
result is itself a job-level infrastructure refusal, and the aggregate fails
closed on the missing output.

The outer CI job timeout is a final containment boundary, not the normal command
deadline. Under ordinary operation, a command timeout plus cleanup and artifact
upload MUST complete before the job timeout can fire.

### Deadline policy

Deadlines MUST be declared in a versioned plan and MAY vary by target or command
class. They MUST NOT silently learn larger values from recent observed runtime.
Changing a deadline changes the plan digest.

Deadlines MUST fit the job that hosts them. For each target, the plan MUST
declare a critical-path budget: the sum of the declared deadlines along the
longest expected sequential path, plus explicit reserves for environment
setup, cleanup, and artifact upload, MUST NOT exceed the job's outer
`timeout-minutes`. Satisfying this may require raising a job timeout, lowering
deadlines, or decomposing a job; whichever is chosen is a plan decision and
changes the plan digest. In addition, the envelope MUST apply launch-time
admission control: a command MUST NOT start if its declared deadline plus the
cleanup and upload reserve exceeds the remaining job budget. A refused launch
is recorded as an infrastructure failure of the attempt — never as a command
failure and never as an absent or unsupported target.

The first implementation SHOULD use deliberately conservative classes, then
tune them from retained measurements. Initial planning values are:

| Command class | Initial deadline |
| --- | ---: |
| Preflight and metadata checks | 10 minutes |
| Engine build or attestation | 30 minutes |
| Public fixture shard | 30 minutes |
| Rust default-feature product suite | 90 minutes |
| Rust all-features product suite | 120 minutes |
| Other product prerequisite | 60 minutes |

Target-specific overrides are permitted when committed to the plan. A timeout
is a failed attempt, not a slow success. Because a failed predecessor stops
dependent phases, the LLP 0021 conformance report may never be built for a
failed run; visibility therefore lives in a separate, always-produced
execution-outcome record that lists every attempt with its classification
(success, failure, timeout, cancellation, refused launch, cleanup failure,
runner loss). The outcome record is a diagnostic artifact, distinct from the
promotion-facing conformance report, and is produced for successful runs too.

Commands not covered by a listed class (recipe generation, the
adapter-evidence batch, the fixture-evidence command, report construction, the
alias-conformance entry point, and any enumerated helpers) take authored
per-command deadlines in the plan; implementers do not invent classes.

Summed along the sequential path, these planning values fit neither current
job budget — not the 180-minute macOS job nor the 240-minute Windows job.
Adopting them requires the critical-path reconciliation above (larger job
timeouts — noting the 360-minute hosted-runner ceiling — tighter deadlines
from measured runtimes, or job decomposition that preserves the same-runner
authority rule) as part of Stage 1, expressed as a complete per-command
mapping for each current target. The table above is a planning placeholder
superseded by that mapping.

Admission control needs the remaining job budget, which hosted runners do not
expose. The declared outer timeout is part of the immutable suite plan and its
digest. The job's start time is per-attempt: it is recorded in a per-attempt
outer-budget record, an operational input rather than authoritative evidence,
and it does not enter the suite-plan digest — so resumption compatibility
compares plan digests without being broken by a new job's start time. Stage 1
MUST also retain per-command duration measurements in the uploaded evidence so
later tuning is grounded in data rather than re-estimation.

### Process-tree termination

On deadline or cancellation, the command envelope MUST stop the entire process
tree it created and MUST record whether cleanup completed.

The containment threat model is accidental, not adversarial: commands are
trusted repository code that may hang or leak children, not hostile programs
engineering their own escape. A descendant that deliberately leaves its
process group (via `setsid` or double-fork) defeats group-based termination;
the required defense against that case is detection, not containment — an
escape that cannot be ruled out is a cleanup-proof failure, which sets the
contamination marker and fails closed. Defense against deliberately malicious
workloads is the aggregate's job (reject what cannot be proven), not the
envelope's.

On POSIX systems, the implementation SHOULD place the command in a dedicated
process group, send a graceful termination signal, wait for the declared grace
period, and then forcibly kill remaining descendants. Grace periods are
authored in the plan alongside deadlines.

On Windows, the implementation SHOULD use a Job Object configured to terminate
all associated processes. A tree-aware platform fallback is acceptable only if
the implementation can prove that the processes it terminates belong to the
attempt. Terminating only the direct child is insufficient.

Failure to prove that descendants were cleaned up invalidates the attempt and
MUST leave a persistent contamination marker that the envelope checks before
launching any command. The marker's storage scope matches the resumption
scope: within a job it lives in supervisor state; on a persistent runner whose
state spans jobs, it MUST live in the same persisted location as the evidence
state it protects, so workspace cleanup cannot erase the marker while leaving
the runner authoritative. No later authoritative phase may run in a
potentially contaminated runner; the marker is what makes that prohibition
enforceable rather than advisory.

### Secure diagnostics

Partial stdout and stderr MUST be retained in the existing secured command-log
area, subject to the ownership, identity, and digest checks required by the
CapSec evidence tooling. Timeout and cancellation MUST not weaken those checks.

CI SHOULD upload the live-status record, command records, and secured diagnostic
bundle on success, failure, timeout, and cancellation whenever the runner is
still available. Uploading a diagnostic artifact does not make it authoritative
evidence, and uploaded copies are never the substrate for authoritative
resumption (which is in-job or persistent-runner state).

Workflow-authored diagnostic files (written by CI steps rather than by the
envelope) MUST live outside the secured evidence namespace, so the aggregate's
exact-membership rule never meets uncontrolled files in evidence paths. One
existing instance must move as part of Stage 1: the Windows job's "Retain
Windows engine-profile preflight state" step writes a workflow-authored
`status.txt` inside the `capsec-suite-evidence-*` namespace.

## Phase graph

The authoritative suite SHOULD expose these named phases:

1. **preflight** — validate repository, target, toolchain, and plan inputs;
2. **engine-attestation-before** — build or identify the reviewed engine and
   bind its initial identity;
3. **recipe-catalog** — construct and validate the expected recipe set (recipe
   generation runs through the command envelope like every other command);
4. **adapter-evidence** — execute adapter conformance work;
5. **public-fixture-evidence** — execute the declared public fixture shards;
6. **public-evidence-aggregate** — validate and assemble public fixture output;
7. **product-prerequisites** — run the broad build and test commands required by
   the target cell;
8. **fixture-evidence** — construct the fixture-evidence binding, execute the
   fixture-evidence command (today the exact-fixture-evidence pilot — the
   producer of the evidence LLP 0021 credits as fixture passes), validate the
   resulting artifact, execute any explicitly requested LLP 0035 portable
   public-batch reruns under their separately budgeted dynamic command class,
   and recheck source-tree immutability;
9. **engine-attestation-after** — prove the authoritative engine did not change
   during execution; and
10. **final-aggregate** — assemble the report defined by LLP 0021 (report
    construction also runs through the command envelope).

This order deliberately corrects the current runner, which attests the engine
*before* running the fixture-evidence pilot. The final attestation MUST follow
every engine-using evidence phase; an attestation that brackets only part of
the engine-using work does not establish identity continuity.

Every evidence producer that feeds the LLP 0021 report has a place in this
graph or an explicit classification outside it:

- **Output-disposition evidence** (the output-shape sweep) is an authoritative
  conformance input when supplied. If produced within the suite it is a phase
  subject to every rule here; if produced by a separate orchestrated run and
  supplied as input, the existing binding checks (source, target, engine)
  remain the acceptance gate and the supplying run must itself satisfy this
  specification to be authoritative.
- **Inherited-intrinsic alias conformance** (the separate macOS step) is a
  distinct conformance entry point. It MUST run under the command envelope,
  and its output is treated as diagnostic until LLP 0021 explicitly assigns it
  an authority class.
- **Supplied fixture evidence** (`--fixture-evidence`): when an externally
  produced fixture-evidence artifact is supplied instead of executing the
  pilot, the same rule as output-disposition evidence applies — the existing
  binding checks (source, target, engine, catalog) are the acceptance gate,
  and the supplying run must itself satisfy this specification for the result
  to be authoritative. (`--public-surface-evidence` is different: it is only a
  redundancy cross-check against locally executed evidence, not a producer.)
- **Adapter evidence** is diagnostic at publication per LLP 0021; the
  `adapter-evidence` phase is required execution, but its output never counts
  as fixture passes.
- **`--expect-incomplete` refusal artifacts** (`capsec-ci-status.json`) are
  diagnostic status records, never promotion evidence.

Per-target evidence eligibility (for example, current Windows limits on
mapped-image provenance) is governed by LLP 0021 and LLP 0013 and is not
changed by this document.

The "supplying run must itself satisfy this specification" obligation on
external producers (output-disposition sweeps, supplied fixture evidence) is
deliberately not assigned to a stage: no target is promotable today, so
nothing regresses, and the obligation binds at the moment externally produced
evidence is first used in a promotion-facing aggregate — whichever stage that
happens in.

Dependencies MUST be explicit. A phase may start only after all required
predecessor outputs have been validated. Implementations may subdivide a phase
without changing this order or authority boundary.

## Resumption

Resumption reuses validated outputs; it does not skip work because a file
happens to exist.

A phase output is reusable only when all of the following match the new attempt:

- plan digest;
- source revision and source-tree digest;
- target and feature configuration;
- tool and runner requirements;
- conformance input digests;
- reviewed engine requirement and artifact identity; and
- every predecessor output digest on which the phase depends.

The source tree and declared plan inputs MUST remain immutable for an
authoritative run. If they change, a new plan is required.

A retry creates a new attempt record. The aggregate MUST retain failed attempt
metadata and MUST select exactly one successful attempt for every expected
phase or shard. Selection MUST be deterministic and recorded: the first
successful attempt in attempt-identifier order is selected, and any later
successful attempt is recorded as superseded-unused. An aggregate that cannot
prove which attempt was selected, or whose inputs contain a successful attempt
it cannot classify, fails.

**Scope of authoritative resumption.** Under the current engine-identity
model, authoritative resumption is limited to the same runner whose engine
identity and contamination state remain provable — in practice, retry within
the same CI job (or on a persistent self-hosted runner that preserves the
mapped engine and evidence state). GitHub-hosted job retries provision a new
machine; the same host-local-identity argument that prohibits cross-runner
sharding applies to a replacement runner. Therefore recovery after an outer
job timeout, job cancellation, or runner loss is diagnostic-only until the
Stage 4 portable-provenance work exists. The Motivation's "successful earlier
work is lost" cost is fully recovered only at Stage 4; Stages 1–3 reduce how
often that loss happens (bounded commands, early failure) and how much
re-execution an in-job retry needs.

## Sharding

### Shard manifest

Every shard MUST carry a canonical manifest containing at least:

- schema version;
- plan digest;
- source revision and source-tree digest;
- target triple, profile, and feature set;
- coverage-map, registry, vocabulary, policy, and implementation digests;
- recipe-catalog digest;
- reviewed engine profile and artifact identity;
- shard identifier and authority class;
- suite-run-instance identifier (assigned by the trusted supervisor; see
  Authoritative sharding);
- expected command, recipe, and fixture identifiers;
- timeout-policy version;
- producer implementation and version;
- attempt identifier; and
- declared output names and digests.

The manifest itself MUST be included in the shard digest (with the self-digest
field excluded from the digest input, per the canonical-form rule in
Terminology). Manifest validation is exact-field: the aggregate MUST reject
any unknown field and any unknown or unsupported schema version, rather than
guessing whether a newer semantic contract is compatible.

Phase, shard, attempt, and live-status records are versioned schemas from
Stage 2 onward — they are load-bearing for resumption and aggregation, so
their format cannot remain informal. The exact closed field sets, digest
domain strings, self-digest projections, and golden test vectors for these
schemas are a Stage 2 deliverable in the conformance tooling; this document
fixes the rules they must obey, not their byte-level layout. Attempt
identifiers are assigned monotonically by the supervising envelope and
recorded, so attempt-order selection cannot be steered by choosing an
identifier.

### Diagnostic sharding

Diagnostic shards MAY execute concurrently on different runners. They SHOULD be
used early to expose target-specific, fixture-specific, or product-suite
failures without waiting for the full authoritative sequence.

Diagnostic artifacts MUST use a distinct authority label and storage path.
The authoritative aggregator MUST reject them even when every other digest
matches. CI presentation MUST not describe a diagnostic pass as conformance or
promotion readiness.

### Authoritative sharding

Under the current Ibex engine-identity model, authoritative shards MUST run on
the same runner and against the same exact mapped engine artifact. Each shard
MUST attest the engine before and after its work. The final aggregate MUST prove
that every accepted shard and both suite-level attestations identify the same
artifact.

Host-local identity fields alone cannot prove that two manifests came from one
machine, and an authority label is self-asserted unless something trusted
assigned it. Same-runner authority is therefore established by construction,
not by comparison: a single trusted supervisor process mints an unguessable
suite-run-instance identifier at startup, assigns every authoritative shard,
creates each shard's output channel, and stamps the instance identifier into
every manifest it accepts. The authoritative aggregator runs under that same
supervisor and MUST reject any manifest carrying a different or missing
instance identifier — including one whose every other field matches. A shard
manifest transported from another runner or another run can never enter the
authoritative set, because it cannot carry this run's instance identifier.

Limited concurrency on one runner is permitted only when:

- the runner has sufficient isolated resources;
- commands do not share mutable build, cache, temporary, or evidence paths —
  concretely, per-shard Cargo target directories, cache roots, and temporary
  roots, since today's commands share all three;
- shard-specific paths and process ownership are enforced;
- the mapped engine is immutable to shard processes (read-only mapping or an
  equivalent enforced protection), so concurrency cannot modify or replace it;
  and
- the isolation claim is tested adversarially: a test shard that attempts to
  modify a sibling shard's evidence or the mapped engine must be detected or
  prevented. Collision-avoidance tests alone do not establish isolation.

Same-user sibling processes are not a security boundary. If these conditions
cannot be met cheaply (per-shard target directories imply rebuild cost),
Stage 3 SHOULD conclude that authoritative concurrency is not worth its
provenance surface and keep the authoritative sequence serial — that outcome
is an acceptable result of Stage 3, not a failure of it.

Cross-runner authoritative sharding is prohibited for now. Existing identity
evidence includes host-local properties such as paths and file identity that
cannot be compared safely across runners. Enabling cross-runner authority
requires a separate accepted design for portable engine provenance, including
how an artifact is built, addressed, authenticated, distributed, mapped, and
attested without weakening LLP 0013 or LLP 0021.

### Aggregate validation

The authoritative aggregator MUST reject the run if it observes any of the
following:

- a missing, duplicate, unexpected, or ambiguously selected shard;
- a manifest with an unknown or unsupported schema version, or any unknown
  field;
- a synthesized runner-loss or infrastructure record presented where
  command-produced evidence is required;
- a diagnostic shard in an authoritative input set;
- a plan, source, target, feature, recipe, policy, or implementation mismatch;
- a missing or mismatched engine attestation;
- an unexpected, missing, or duplicate fixture result;
- an output whose digest does not match its manifest;
- a timed-out, canceled, contaminated, or incomplete accepted attempt; or
- a product prerequisite that did not complete successfully.

Aggregation MUST be deterministic. Given the same canonical input manifests and
outputs, it MUST produce the same semantic report regardless of filesystem
enumeration order or attempt completion order.

## CI rollout

Implementation SHOULD proceed in four stages.

### Stage 1: bounded sequential execution

Keep one authoritative runner and the sequential shape of the suite, with one
deliberate ordering change: move the final engine attestation after the
fixture-evidence phase, as the phase graph requires. The current order (attest
before the fixture-evidence pilot) violates the attestation-bracketing MUST
and is corrected here, in Stage 1, not deferred. An additional attestation
checkpoint at the old position MAY be retained as a diagnostic. Introduce the
command envelope, authored deadlines, live status, process-tree cleanup, and
always-uploaded diagnostics. This stage addresses indefinite hangs and unclear
outer-timeout failures without otherwise changing evidence assembly; the
"same semantic report" criterion below is evaluated on the report's semantic
content via the canonical validators, which the attestation reorder does not
change.

### Stage 2: resumable phases

Emit canonical phase manifests and validate dependencies before reuse. Permit a
retry to resume the same plan on the same uncontaminated runner — in-job retry
on hosted CI, or across jobs only on a persistent runner that preserves the
mapped engine, evidence state, and contamination markers between jobs. Stage 2
does not create any cross-machine resumption path; that is Stage 4.

### Stage 3: parallel diagnostics and same-runner authoritative shards

Add cross-runner diagnostic jobs for fast feedback. Where measurements justify
it, add resource-isolated public-fixture shards on the authoritative runner.
The single final aggregate remains the only promotion-facing result.

### Stage 4: portable authoritative distribution

Do not begin this stage until a separate accepted LLP defines portable engine
artifact provenance. Once that exists, this specification should be revised to
bind shard manifests to that identity and to define the trusted aggregate
boundary.

## Security properties

An implementation conforming to this specification preserves these properties:

1. **Fail closed:** incomplete execution never produces a conformant result.
2. **Exact membership:** the aggregate accepts exactly the planned work, once.
3. **Identity continuity:** authoritative evidence remains bound to the reviewed
   engine and immutable inputs.
4. **No authority laundering:** diagnostics, logs, and broad suites cannot be
   relabeled as fixture evidence.
5. **Bounded contamination:** a timed-out process tree is either proven stopped
   or the runner is excluded from further authoritative work.
6. **Auditable retry:** every reused output and replacement attempt has an
   explicit, digest-bound reason.
7. **Target honesty:** infrastructure failure is reported as failure or
   incomplete execution, never as unsupported capability.

## Acceptance criteria

Stage 1 is complete when:

- every conformance command (including generators, report construction, and
  secondary conformance entry points) runs through the command envelope with a
  declared deadline;
- for each target, the declared critical-path budget (deadline sum plus setup,
  cleanup, and upload reserves) fits the job's outer timeout, and launch-time
  admission control refuses commands that no longer fit the remaining budget;
- synthetic hanging parent and grandchild processes are terminated on macOS,
  Linux, and Windows (the Linux case runs in ordinary CI; the conformance
  workflow has no Linux job), and a synthetic descendant that escapes its
  process group or session is detected and classified as a cleanup-proof
  failure;
- timeout diagnostics identify the exact command and are uploaded within a
  bounded cleanup interval;
- a cleanup failure sets the contamination marker and the envelope refuses
  subsequent authoritative work;
- the always-produced execution-outcome record exists for successful, failed,
  timed-out, and canceled runs;
- per-command durations are retained in uploaded evidence; and
- ordinary conformance runs produce the same semantic report as before, where
  "same" is judged by the existing canonical report validators, not informal
  comparison. Stage 1 envelope and outcome records are emitted as parallel
  artifacts rather than reshaping the existing executions artifact, so this
  criterion stays trivially checkable.

Stage 2 is complete when tests prove that:

- a late failure can reuse all valid predecessor phases;
- changes to source, plan, target, engine, or conformance inputs invalidate the
  affected phase and every dependent phase;
- stale, missing, duplicate, corrupted, and ambiguous outputs are rejected;
- failed attempts remain auditable after a successful retry;
- attempt allocation and contamination state are durable and atomic across a
  supervisor crash or restart — a restarted supervisor cannot reuse an attempt
  identifier, lose a contamination marker, or accept rolled-back state, and
  crash-recovery tests cover interruption between attempt allocation, command
  launch, cleanup, and manifest publication; and
- the resumed and uninterrupted runs produce semantically identical reports.

Stage 3 is complete when tests prove that:

- diagnostic results cannot enter the authoritative aggregate;
- shard membership is exact and deterministic;
- a manifest from a different suite-run instance — including one whose every
  other field matches — is rejected by the authoritative aggregator;
- per-shard pre/post engine attestations match; and
- the final aggregate fails closed for every timeout and runner-loss case.

Authoritative concurrency is optional within Stage 3. If it is adopted, tests
must additionally prove that same-runner concurrent shards cannot collide in
build, temporary, log, or evidence paths, and that an adversarial shard
attempting to modify sibling evidence or the mapped engine is prevented or
detected. If it is evaluated and rejected (on isolation cost or risk), Stage 3
is complete with serial authoritative execution and the rejection rationale
recorded in the plan.

Stage 4 deliberately has no acceptance criteria here: it is a placeholder that
cannot be implemented under this document. Beginning it requires an accepted
portable-provenance LLP and a revision of this specification.

No stage is complete if the outer CI timeout is still the first expected
deadline for an individual command.

## Open questions

- Which initial deadline overrides are necessary for Windows and constrained
  macOS runners after representative measurements?
- Should the command envelope be implemented in the existing JavaScript
  evidence runner, as a small platform-native helper, or as a layered pair?
- What Windows Job Object integration best preserves descendant ownership and
  diagnostic collection?
- Which public fixture boundaries offer useful same-runner parallelism without
  increasing shared-state risk?
- What portable artifact identity and attestation scheme would justify
  cross-runner authoritative sharding?
- Should the versioned phase/shard/attempt schemas (required internally from
  Stage 2) ever be published as a public contract, or remain internal to the
  conformance tooling?
- Should output-disposition evidence be folded into this suite as an in-graph
  phase, or remain a separately orchestrated producer accepted through its
  binding checks?
- Where does the versioned suite plan live in the repository (a candidate is
  `capsec/conformance/`), and how is its digest bound into the CI invocation?

## Implementation notes

The existing workflow-level timeouts remain useful as containment, but should
be raised or lowered only after command deadlines and worst-case cleanup/upload
time are known. Buying a faster Linux host may improve the Linux diagnostic and
product-suite lanes; it does not remove the need for this protocol and cannot
substitute for macOS and Windows target evidence.

The first useful code change is intentionally smaller than full sharding:
introduce one cross-platform command envelope, apply it to the current
sequential runner, and make command state visible while CI is running. Runtime
measurements from that stage should determine where sharding actually pays for
its additional provenance surface.
