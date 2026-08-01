# P8 risk routing, evidence assurance, and targeted recheck

Status: completed
Date: 2026-08-01

## Outcome

P8 implements the three mechanisms that form CodeSentinel's main technical
differentiation:

1. deterministic plus semantic-hint risk routing;
2. evidence normalization, validation, deduplication, and conflict detection;
3. one append-only targeted recheck followed by a fresh Policy evaluation.

These are reusable domain components. P8 does not yet connect P5-P8 into one
CLI run or dispatch the roles through AgentTeams; those boundaries remain P9
and P10 respectively.

## Risk routing and Coverage

`RiskRouter` accepts only a validated `DiffAnalysis` and its matching
`cloud_safe=true` P6 view. Its frozen rules identify SQL injection, command
execution, dangerous calls, authorization boundaries, control-flow changes,
exception handling, performance risks, and missing test-file changes. Optional
semantic hints must reference exact sanitized locations; matching rule and
semantic routes become `hybrid` without giving model output any evidence
authority.

The frozen always-on set is:

- `detect_secret`, which protects the source-disclosure boundary;
- `security_semantic_review`, required for the Security Review artifact;
- `review_code_quality`, required for the Quality Review artifact.

`detect_injection` and `detect_dangerous_call` are scheduled only when their
frozen triggers match. Every unplanned Skill receives a concrete skip reason.
`reconcile_coverage` binds completed executions to exact route IDs and emits an
auditable `SKIPPED` or fail-closed `MISSING_EXECUTION_RESULT` record for every
other planned candidate.

Routing IDs, ordering, fingerprints, and plan contents are hash-stable. The
same validated inputs therefore produce byte-equivalent model dumps.

## Evidence assurance

`EvidenceAssurance` reuses the P4 closed-reference validator as the authority
for Schema, review IDs, line locations, artifact lineage, coverage references,
and trusted-E3 qualification. It then provides a normalized read-only view:

- Finding identity is recomputed from category plus exact changed locations,
  independent of the producing Agent;
- evidence identity uses content hash plus exact location;
- valid evidence is preferred over a stronger-looking invalid item;
- original Agent artifacts are never rewritten during deduplication;
- equivalent findings are grouped while retaining all member IDs.

It deterministically detects active-versus-dismissed contradictions, material
severity disagreements, declared-fingerprint location collisions, and routed
coverage gaps. Unresolved conflicts are inserted into the same immutable
Policy context, disqualify conflicting findings from automatic blocking, and
produce `N003 / NEEDS_REVIEW` rather than an unsafe verdict.

LLM evidence remains structurally capped at E1 by the frozen domain contract.
E3 must also be registered by the trusted local verifier and match the policy's
source/detector/version allow-list. A model therefore cannot promote its own
opinion into blocking evidence.

## One targeted recheck

`TargetedRecheckController` first runs evidence assurance and the P4 Policy. A
recheck is considered only for `NEEDS_REVIEW`, and each request contains exact
finding IDs, conflict IDs, Skill names, route IDs, and changed locations. It
cannot request a second full review.

The result boundary enforces:

- attempt number is exactly one;
- original evidence IDs cannot be replaced or reused;
- every new evidence item is linked once and stays within target locations;
- new E3 evidence must be registered by the trusted verifier;
- pure LLM E1 evidence cannot confirm or dismiss a Finding;
- Coverage replacements are restricted to requested Skills and routes;
- conflict resolutions cannot escape the requested conflict set.

Provider failure, timeout, invalid output, or an inconclusive recheck preserves
the original context and marks automatic recheck exhausted. The Policy is then
executed again and emits `N008`. A successful local E3 reproduction can instead
confirm a Finding and produce a deterministic `BLOCK`; repaired mandatory
Coverage can produce `PASS` when no other rule remains.

## Verification

P8 adds 10 focused offline tests covering:

- SQL, shell, auth, and performance routing;
- stable deterministic output;
- always-on secret scanning and explicit skip reasons;
- rule/semantic hybrid merging and semantic-provider failure fallback;
- LLM E3 rejection and unregistered-E3 invalidation;
- normalized Finding deduplication;
- contradiction and severity conflict escalation to `NEEDS_REVIEW`;
- E3 append-and-re-evaluate behavior;
- one-attempt exhaustion, mandatory-Coverage repair, and prevention of
  model-only dismissal.

Acceptance evidence after implementation:

```text
P8 tests: 10 passed
Full P1-P8 tests: 204 passed
Ruff: all checks passed
pip check: no broken requirements found
repository credential-pattern scan: no matches
git diff --check: passed (LF-to-CRLF warnings only on Windows)
```

## Deliberate P8 limitations

- P8 exposes components rather than the P9 single-process CLI loop;
- semantic hints are a strict input boundary; P9 must wire them to the Diff
  Analyzer result and persist their trace;
- recheck execution and wall-clock timeout enforcement belong to the P9 runner;
- Coverage reconciliation is implemented but not yet attached to final run
  artifacts;
- AgentTeams business dispatch, collaboration-room evidence, and Manager
  arbitration remain P10;
- no accuracy claim is made before the P12 gold evaluation set and P13
  ablation experiments.
