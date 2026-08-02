# P10-3B controlled Worker deployment and rollback plan

Date: 2026-08-02

Plan review result: **CONDITIONAL GO**

Execution status: **NOT STARTED; live deployment is not approved by this document**

This plan replaces the stale P10-3B next-action text in the broader P10-3 plan.
It authorizes documentation and readiness review only. It is not evidence that
a Skill was deployed, a task was registered, or a model was called.

## 1. Frozen baseline and invariants

- P10-3A implementation commit: `4ffc1c82a7f870029594fc2f2bc4705c6f1ac9b5`.
- R1 security-correctness commit: `33a5985cd6761bf7bd95e0639a92cab3dc7f766a`.
- The deployment baseline is the future accepted clean documentation commit
  that contains this plan and has R1 as an ancestor. Its exact SHA is `TBD`
  until that commit is separately approved, created, and pushed.
- At build time, local `HEAD`, `origin/main`, the recorded source revision, and
  the bundle manifest must agree, and `source_dirty` must be `false`.
- The three Workers remain on `hiclaw-gateway/deepseek-v4-pro`.
- Manager model-call delta must remain zero.
- Domain analyses must not exceed four; aggregate Worker provider-call delta
  must not exceed eight.
- P9 remains the fallback and Dify must remain stopped.

The plan file itself makes the working tree dirty. Therefore no deployment may
start until this plan is committed and pushed with separate approval.

## 2. Exact scope

P10-3B may deploy and validate only these mappings:

| Order | Worker | Skill |
|---|---|---|
| 1 | `cs-diff-analyzer` | `codesentinel-diff-review` |
| 2 | `cs-security-scanner` | `codesentinel-security-review` |
| 3 | `cs-quality-reviewer` | `codesentinel-quality-review` |

It may use the existing deterministic runtime bundle to validate assignments,
role payloads, evidence lineage, hashes, and authoritative deliveries.

P10-3B must not implement Manager autonomy, parallel dispatch, final gate
decisions, repository mounts, container recreation, gateway changes, key
changes, route changes, or any P10-4 claim.

## 3. Approval and execution slices

Every slice ends with a report. A hard-stop condition ends the whole run.

### P10-3B-0: clean-baseline read-only preflight

1. Verify the accepted plan commit is pushed and local `HEAD == origin/main`.
2. Require an otherwise clean working tree; the excluded health-audit report
   may remain untracked only if it is outside every bundle and staging input.
3. Read Docker, AgentTeams, Dify, route, room, registry, finite-task state,
   remote Skill listing, and Worker call-count state without mutation.
4. Confirm the five expected AgentTeams containers are healthy and no Dify
   container is running.
5. Confirm the official Skill-management and task-state scripts exist and
   record their hashes and observed behavior.

Acceptance: zero state change, zero model calls, exact targets identified, and
all observations recorded. Otherwise stop before staging.

### P10-3B-1: reproducible build and isolated staging

1. Build the runtime bundle twice from the accepted clean commit.
2. Require byte-identical bundles, matching SHA-256 values, the accepted
   source revision, and `source_dirty=false`.
3. Materialize one deployment package at a time in an isolated Manager-side
   staging directory; never modify the repository source template in place.
4. Replace every deployment-manifest placeholder with the accepted source
   revision and runtime-bundle reference/hash.
5. Run the package-local runtime-binding verifier, secret scan, archive-content
   allow-list check, and offline delivery validation.
6. Record package tree hashes before any remote copy.

Acceptance: three independently valid packages, zero placeholders, zero
credentials, zero absolute host paths, zero model calls, and no Worker change.

### P10-3B-2: Diff Worker canary

1. Snapshot the exact Worker registry, existing Skill path, room ID, route,
   call count, task state, and relevant remote hashes.
2. Back up an existing exact Skill version if present.
3. Deploy only `codesentinel-diff-review` to `cs-diff-analyzer` through the
   official management script with `--no-notify`.
4. Verify repository, staged, remote, and Worker-visible package hashes.
5. Register one bounded finite task, publish its artifacts, send the complete
   assignment to the Worker's own room, and require task acknowledgement.
6. Pull the submitted authoritative `workspace/delivery.json`; independently
   validate role, review, task, assignment, schema, paths, hashes, evidence
   lineage, deadline, attempt, and model-usage fields.
7. Record the provider-call delta and preserve taskflow and artifact evidence.

Acceptance: one valid Diff delivery, no cross-role output, no chat-only
completion, and no unexpected state change. Stop for review before Security.

### P10-3B-3: Security Worker

Repeat the canary procedure only for `codesentinel-security-review` on
`cs-security-scanner`. Security semantic findings must cite the bounded trusted
scan/context lineage and must not invent E2/E3 evidence or a gate decision.
Stop for review before Quality.

### P10-3B-4: Quality Worker

Repeat the canary procedure only for `codesentinel-quality-review` on
`cs-quality-reviewer`. Quality findings must remain within correctness,
reliability, maintainability, and performance scope. They must not perform the
Security or Gate role.

### P10-3B-5: evidence closure

1. Pull and independently revalidate all three deliveries.
2. Create one evidence manifest containing source, bundle, Skill, task,
   delivery, route, and usage hashes/references without secret values.
3. Verify the aggregate domain-analysis and provider-call budgets.
4. Remove only verified temporary Manager-side staging files.
5. Recheck routes, containers, Dify stopped state, active finite-task state,
   Git state, and P9 regression health.
6. Report only the claims actually demonstrated; do not claim concurrency,
   autonomous orchestration, or a final gate.

## 4. Mandatory checkpoints

The current approval covers only plan creation and review. Later execution
requires explicit approval after the plan commit is pushed.

- Gate A: approve P10-3B-0 and P10-3B-1.
- Gate B: after their evidence passes, approve the Diff canary.
- Gate C: after Diff passes, approve the Security Worker.
- Gate D: after Security passes, approve the Quality Worker and evidence
  closure.

No failed or ambiguous checkpoint may be waived by a convincing chat response.

## 5. Acceptance criteria

P10-3B is accepted only when all of these are true:

- the accepted clean source commit contains R1 and this reviewed plan;
- `HEAD == origin/main`, manifest source revision matches, and
  `source_dirty=false`;
- every Skill exists only on its intended Worker;
- repository, staging, remote, and Worker-visible hashes agree;
- each finite task is registered, acknowledged, and submitted through the
  official taskflow;
- every task produces a strict, independently valid `workspace/delivery.json`;
- role, schema, review, task, assignment, path, hash, deadline, attempt, and
  evidence-lineage checks all pass;
- three normal domain analyses are used, with at most one targeted repair;
- domain-analysis count is at most four and provider-call delta is at most
  eight; Manager model-call delta is zero;
- routes, containers, Dify state, secrets, and P9 fallback remain within the
  frozen boundaries;
- no unsupported P10-4 claim is made.

Any missing criterion means **P10-3B not accepted**.

## 6. Rollback matrix

| Trigger | Exact rollback | Evidence preserved |
|---|---|---|
| Package or binding validation fails before deployment | Delete only the verified isolated staging copy; do not touch a Worker | Build logs, manifests, hashes, scan output |
| Skill copy, registry, or hash verification fails | Remove only the exact affected Skill after backup and target re-verification; restore the prior exact version if present | Failed package, registry snapshots, remote and local hashes, script output |
| Task acknowledgement, model, or submission fails | Stop the role; preserve the task directory and usage snapshot; clear only its active Manager task state after recording failure | Task metadata, Matrix references, result candidate, delivery candidate, logs, usage delta |
| Delivery validation or role isolation fails | Reject the delivery; do not continue to the next Worker; use the single repair slot only if both budgets allow | Invalid delivery, validation errors, all source artifacts and hashes |
| Route, container, Dify, credential boundary, or budget changes unexpectedly | Stop immediately; roll back only the affected exact Skill when safe; leave infrastructure unchanged for diagnosis | Before/after topology, route, usage, registry, and event evidence |
| Exact rollback target cannot be proven | Perform no deletion or restart; stop and request a new decision | All snapshots and the unresolved target evidence |

Rollback never runs `docker compose down`, recreates a Worker, changes a
gateway or API key, deletes a volume, resets Git, deletes Matrix/MinIO evidence,
or restarts a Worker without separate approval.

## 7. Hard-stop conditions

Stop immediately when any of the following occurs:

- source commit, cleanliness, bundle hash, package hash, or target identity is
  missing or inconsistent;
- a credential, raw secret, absolute host path, or unbounded raw patch would
  reach Matrix, MinIO, or a Worker;
- a Skill appears on the wrong Worker;
- a Worker produces a wrong-role, wrong-review, invalid-schema, invalid-path,
  invalid-hash, cross-lineage, late, wrong-attempt, or chat-only result;
- call-count measurement is unavailable, the 4/8 budget would be exceeded, or
  an automatic retry would be required;
- a route, container, Dify state, gateway, key, or unrelated Worker changes;
- rollback cannot identify one exact recoverable target.

## 8. Plan audit result and next action

The plan is **GO for a plan-only commit** and **NO-GO for live deployment**.
It preserves the competition-relevant claims of role isolation, official
finite-task use, deterministic evidence, reproducibility, observability, and
fail-closed behavior while preventing P10-4 claims from leaking into P10-3B.

Before execution, the user should review this file, approve a documentation-only
commit and push, then separately approve Gate A. No deployment, model call, or
AgentTeams mutation may occur before that sequence is complete.
