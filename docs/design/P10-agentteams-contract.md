# P10 AgentTeams integration contract

Status: **frozen for P10 implementation**

Contract version: `1.0.0`

AgentTeams baseline: `v1.1.2`

CodeSentinel baseline: P9 commit `3a68b4ac255e52448f1921ad273d6cd8f0bfd7f2`

This document freezes the boundary, orchestration, artifact, budget, timeout,
security, and rollback rules for P10. It is an implementation contract, not
evidence that the multi-agent workflow is already complete.

## 1. P10 objective and non-goals

P10 must prove a real Manager–Workers workflow in AgentTeams:

1. the Manager delegates to the Diff Analyzer Worker;
2. after a validated diff result, the Manager delegates to the Security
   Scanner and Quality Reviewer Workers concurrently;
3. Workers submit schema-valid artifacts rather than chat-only conclusions;
4. the Manager validates evidence and invokes deterministic policy logic;
5. a human can inspect, cancel, and replay the complete review trace.

P10 does not change the P9 gate semantics, add a fifth agent, expose a local
repository to containers, alter the AgentTeams model gateway, or build the P11
demo set. A P9 local run remains the stable fallback.

## 2. Frozen topology

| Component | Frozen responsibility | Must not do |
|---|---|---|
| Host boundary adapter | Read local Git diff, run deterministic intake checks, redact secrets, publish cloud-safe input, validate and persist the final result | Upload raw secrets, give containers a repository mount, decide the gate with an LLM |
| Gate Arbiter Manager | Register finite tasks, dispatch work, validate references and schemas, merge evidence, request at most one targeted repair/recheck, invoke deterministic policy | Perform Diff/Security/Quality discovery itself, invent missing evidence, override policy |
| Diff Analyzer Worker | Produce structured change semantics and risk-map candidates | Decide security, quality, or gate outcome |
| Security Scanner Worker | Review the trusted deterministic security scan and perform semantic security analysis | Receive raw secrets, decide the gate, silently downgrade scanner failures |
| Quality Reviewer Worker | Perform semantic correctness, reliability, and performance review | Decide security or gate outcome |
| Deterministic Policy Engine | Produce `PASS`, `BLOCK`, or `NEEDS_REVIEW` from validated evidence | Call a model or infer missing evidence |

The existing Manager and the three existing Worker rooms are reused. P10 does
not create an AgentTeams Team or a fifth Team Leader. Cross-room correlation
uses `review_id`, `trace_id`, task IDs, artifact references, and event IDs.

## 3. Trust and data boundary

The local repository is the trust boundary. It remains host-only and is read
through the P5 read-only Git adapter. Neither the Manager nor any Worker gets a
bind mount to the current CodeSentinel repository or to the reviewed target
repository.

Before any Matrix message or MinIO upload, the host boundary adapter must:

1. read the selected Git diff without mutating the repository;
2. run the complete P6 deterministic security suite, including secret checks;
3. redact detected secret values and unsafe metadata;
4. produce a canonical JSON artifact with `cloud_safe=true`;
5. hash the canonical bytes with SHA-256;
6. reject the review if any serialization, redaction, or hash check fails.

Matrix messages carry only control information and relative artifact
references. Source code, patches, credentials, upstream API keys, absolute host
paths, MinIO credentials, and gateway consumer keys must never appear in a
Matrix message or public trace.

## 4. Runtime plan

### 4.1 Control plane and data plane

- Matrix is the control plane: assignment, acknowledgement, status, completion,
  blocker, cancellation, and human-visible evidence references.
- MinIO-backed `shared/` paths are the data plane and authoritative artifact
  transport.
- `/root/hiclaw-fs` is not treated as realtime storage. Every read follows an
  explicit pull, and every published artifact follows an explicit push and
  verification.
- AgentTeams built-in finite-task registration remains authoritative for task
  liveness; every delegated Worker task must be registered before waiting for
  its result.

### 4.2 Runtime package strategy

P10 uses versioned AgentTeams Skill packages plus a versioned CodeSentinel
runtime bundle. The bundle is generated from the reviewed repository commit,
has a manifest and SHA-256 digest, contains no credentials, and is distributed
through the official shared-storage/Skill workflow.

The runtime bundle is executed with each role's existing CoPaw Python runtime.
It must not install packages into a running container, mutate a base image, or
depend on an untracked container change. P10-2 must first prove that the bundle
can load and validate a fixture inside Manager and Worker containers. Business
integration cannot proceed if that compatibility gate fails.

P6 scanners that require host-only dependencies run at the trusted ingress
boundary. Their complete, hashed evidence is assigned to the Security task.
Semantic model reasoning is performed by the actual CoPaw Worker through the
AgentTeams gateway. The P7 direct provider remains available only to the P9
fallback runner and is not used to fake AgentTeams Worker activity.

If the isolated bundle compatibility gate fails, P10 stops for review. The
approved fallback is a reproducible derived Worker template/image pinned to
AgentTeams `v1.1.2`; manual `pip install` in live containers is forbidden.

## 5. Identifiers and task layout

All IDs are generated once and remain immutable:

- `review_id`: one complete PR review attempt;
- `trace_id`: one end-to-end observable trace;
- `task_id`: one AgentTeams finite task;
- `attempt`: `1` for the normal task and `2` only for the single reserved
  repair/recheck;
- `parent_task_id`: the Manager orchestration task or the preceding Diff task.

Recommended task IDs use
`task-YYYYMMDD-HHMMSS-<role>-<review8>` and contain only lowercase ASCII,
digits, and hyphens.

Canonical review artifacts use relative paths under:

```text
shared/projects/codesentinel/reviews/<review_id>/
  request.json
  input/sanitized-diff.json
  input/deterministic-security.json
  results/diff-analysis.json
  results/security-review.json
  results/quality-review.json
  results/gate-decision.json
  trace/agentteams-trace.json
  manifest.json
  cancel.json                 # only when cancelled
```

Each Worker receives immutable inputs under
`shared/tasks/<task_id>/base/` and submits its structured result under
`shared/tasks/<task_id>/workspace/delivery.json`. The standard AgentTeams
`meta.json`, `spec.md`, and `result.md` remain compatible with built-in task
management. CodeSentinel-specific fields live in separate JSON files instead
of changing the AgentTeams metadata schema.

## 6. Review request envelope

`request.json` must validate against the following logical contract:

```json
{
  "schema_name": "CodeSentinelAgentTeamsReviewRequest",
  "schema_version": "1.0.0",
  "review_id": "review-...",
  "trace_id": "trace-...",
  "root_task_id": "task-...-manager-...",
  "input_artifact_ref": "shared/projects/codesentinel/reviews/.../input/sanitized-diff.json",
  "input_sha256": "64 lowercase hex characters",
  "policy_version": "p4-policy-v1",
  "runtime": "agentteams-v1.1.2",
  "budget": {
    "max_domain_model_calls": 4,
    "max_total_model_calls": 8,
    "max_reserved_repair_or_recheck_calls": 1
  },
  "deadline_at": "RFC3339 UTC timestamp",
  "cloud_safe": true
}
```

Unknown schema major versions, missing identifiers, unsafe paths, digest
mismatches, `cloud_safe=false`, and expired deadlines are fail-closed input
errors. They never enter AgentTeams.

## 7. Worker delivery envelope

Every Worker `delivery.json` contains:

```json
{
  "schema_name": "CodeSentinelAgentTeamsWorkerDelivery",
  "schema_version": "1.0.0",
  "review_id": "review-...",
  "trace_id": "trace-...",
  "task_id": "task-...",
  "parent_task_id": "task-...",
  "role": "diff_analyzer | security_scanner | quality_reviewer",
  "attempt": 1,
  "status": "SUCCESS | SUCCESS_WITH_NOTES | REVISION_NEEDED | BLOCKED",
  "input_artifacts": [
    {"ref": "shared/...", "sha256": "..."}
  ],
  "output": {},
  "evidence": [],
  "started_at": "RFC3339 UTC timestamp",
  "finished_at": "RFC3339 UTC timestamp",
  "model_usage": {"calls": 1},
  "output_sha256": "64 lowercase hex characters"
}
```

`output` is the existing P7/P8 role schema, not free-form markdown. Evidence
must retain file path, line span, rule/source, confidence, and artifact lineage
where applicable. `result.md` is a short human-readable summary that references
the JSON delivery and never substitutes for it.

The Manager rejects a delivery if its IDs, role, attempt, input digests, schema,
artifact path, or output digest do not match the registered task. Rejected
deliveries are retained in the trace but cannot affect the gate.

## 8. State machine and orchestration

The review state machine is:

```text
CREATED
  -> INGRESS_SAFE
  -> DIFF_ASSIGNED
  -> DIFF_COMPLETED
  -> REVIEWS_ASSIGNED
  -> REVIEWS_COMPLETED
  -> EVIDENCE_VALIDATED
  -> [REPAIR_OR_RECHECK_ASSIGNED -> EVIDENCE_VALIDATED]
  -> POLICY_EVALUATED
  -> PERSISTED
  -> COMPLETED
```

Terminal exceptional states are `CANCELLED` and `FAILED`. Timeouts, missing
mandatory evidence, schema failures after the reserved retry, Worker blockers,
and inconsistent hashes produce a deterministic `NEEDS_REVIEW` or technical
failure according to the P4 policy boundary; they must never silently become
`PASS`.

Frozen dispatch order:

1. Host publishes a safe request and notifies the Manager.
2. Manager creates, pushes, registers, and sends the Diff task.
3. Manager pulls and validates the Diff delivery.
4. Manager creates and pushes both Security and Quality tasks before sending
   both assignments.
5. Security and Quality execute independently in separate Worker rooms.
6. Manager pulls both deliveries and validates evidence lineage.
7. If necessary, Manager spends the one shared reserve call on either schema
   repair or targeted semantic recheck, never both.
8. Manager invokes the deterministic Policy Engine and publishes the decision.
9. Host independently verifies the same policy result and persists the trace.

The concurrency acceptance test requires overlapping
`started_at`–`finished_at` intervals for Security and Quality. Dispatch messages
alone do not prove parallel execution.

## 9. Budgets, retries, and timeouts

The user-approved budget is frozen as follows:

| Budget | Limit | Rule |
|---|---:|---|
| Normal domain model calls | 3 | Diff, Security, Quality: one each |
| Reserved domain call | 1 | One schema repair **or** one targeted semantic recheck |
| Domain model calls per review | 4 | Hard maximum |
| Total AgentTeams model calls per review | 8 | Includes Manager orchestration |
| Dispatch retry | 1 | Same task ID, only if acknowledgement is absent |
| Full workflow deadline | 300 s | Never extended by retry |
| Diff task allowance | 75 s | Within the full deadline |
| Security/Quality allowance | 120 s | Concurrent, within the full deadline |
| Reserved repair/recheck | 60 s | Only from remaining deadline |

Deterministic tool execution and schema validation do not consume model-call
budget. A duplicate message with the same task ID is idempotent and does not
authorize a second model call. If the reserve call was already consumed, any
remaining ambiguity fails closed to `NEEDS_REVIEW`.

## 10. Deterministic gate contract

The Manager is the Gate Arbiter but not the gate policy. It may explain the
result, yet the final enum must come from the existing deterministic Policy
Engine. Its inputs are only validated Worker outputs, deterministic scanner
evidence, evidence-assurance results, policy version, and bounded recheck
status.

The host boundary adapter repeats the policy calculation over the persisted
inputs. A Manager/host decision mismatch is a technical integrity failure and
forces `NEEDS_REVIEW`; it is never resolved by asking an LLM which value is
correct.

## 11. Human control and cancellation

The Manager Skill exposes a reviewed control message:

```text
CODESENTINEL_CANCEL <review_id> <reason>
```

Only the authorized admin room may issue it. Cancellation is cooperative and
auditable: the Manager writes `cancel.json`, stops creating new tasks, sends a
cancellation notice to active Worker rooms, ignores late deliveries for policy
purposes, and records those late events in the trace. It does not delete task
data, kill containers, or erase messages.

## 12. Trace and replay contract

The final trace must contain, without credentials or raw secret values:

- review, trace, task, parent-task, room, and Matrix event identifiers;
- AgentTeams and CodeSentinel versions and runtime-bundle digest;
- state transitions with UTC timestamps;
- assignment, acknowledgement, completion, timeout, and cancellation events;
- relative artifact references and SHA-256 digests;
- per-role model-call counts and total budget usage;
- validation failures, rejected deliveries, repair/recheck reason;
- Policy Engine inputs, policy version, outcome, and independent verification.

Replay verifies artifacts and re-runs deterministic validation/policy without
calling a model. Re-running the semantic Agents is a new review attempt with a
new `review_id`, not a deterministic replay.

## 13. Failure and rollback rules

P10 uses these stop conditions:

- any credential or raw secret reaches Matrix/MinIO;
- model routing changes from `deepseek-v4-pro` or bypasses `hiclaw-gateway`;
- a role cannot load its pinned Skill/runtime bundle reproducibly;
- a Worker returns only chat text after the one reserved repair;
- Manager discovers findings itself or overrides deterministic policy;
- artifact lineage, call budget, cancellation, or trace cannot be proven.

Rollback is staged and non-destructive:

1. stop the active review and preserve Matrix/MinIO evidence;
2. disable only the CodeSentinel P10 Skill/runtime package;
3. restore the prior package version/digest and restart only the affected role
   when necessary;
4. verify Manager and all Workers still use `deepseek-v4-pro` through
   `hiclaw-gateway`;
5. use the P9 local runner at commit `3a68b4a` as the stable fallback;
6. use `git revert` for reviewed P10 code commits—never reset or delete shared
   storage.

No rollback may run `docker compose down`, remove AgentTeams volumes, change
gateway credentials, or delete Matrix/MinIO history.

## 14. Dify coexistence decision

Dify is outside the P10 runtime and is safely stopped during AgentTeams work to
reduce resource contention. Its containers, restart policies, configuration,
and volumes remain unchanged. Because the Dify containers use an automatic
restart policy, their state must be checked again after Docker Desktop restarts.

## 15. P10-2 entry gate

P10-2 may start only after this document is reviewed and must first implement a
small compatibility slice, not the complete workflow. The slice must prove:

1. a pinned runtime bundle loads in Manager and one Worker without live
   installation;
2. a fixture request and Worker delivery pass strict schema and hash checks;
3. Matrix carries only control metadata and MinIO carries the artifact;
4. no model call is made by the compatibility test;
5. removing the bundle returns AgentTeams to the unchanged P3 baseline.

Passing this gate authorizes later P10 slices; it does not by itself satisfy P10
or the competition's multi-agent requirement.
