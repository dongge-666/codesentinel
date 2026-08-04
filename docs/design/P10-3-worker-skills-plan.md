# P10-3 Worker Skills deployment and structured-delivery plan

Date: 2026-08-01

Review result: **CONDITIONAL GO**

Execution status: **P10-3A, P10-3B Gate A, and the Diff Worker canary are complete; stopped before Security pending Gate C**

This document reviews the P10-3 implementation and rollback plan. It is not
evidence that any role Skill has been installed or that any model task has
been executed.

## 1. Review conclusion

P10-3 is feasible on the accepted P10-2 baseline. The three existing Workers,
their DeepSeek routes, AgentTeams finite-task protocol, MinIO data plane, and
the minimal CodeSentinel runtime are sufficient for a controlled deployment.

Execution is approved by design only if it is split into two separately
reviewed slices:

1. **P10-3A — offline implementation:** add the role contracts, deterministic
   delivery builder, three versioned Skill packages, fixtures, and tests;
2. **P10-3B — clean-baseline deployment:** after P10-3A is reviewed, committed,
   and pushed with separate approval, rebuild from that clean commit and deploy
   and validate one Worker at a time.

This split is mandatory. Deploying from the uncommitted P10-3 working tree
would produce `source_dirty=true` and weaken the reproducibility and audit
evidence expected for the competition.

## 2. Scope and non-goals

P10-3 will prove that each existing Worker can receive only its own Skill and
submit one strict, machine-validated delivery through the official AgentTeams
finite-task workflow.

P10-3 will not:

- implement autonomous Manager orchestration;
- run Security and Quality concurrently;
- calculate or claim a final `PASS`, `BLOCK`, or `NEEDS_REVIEW` result;
- change the gateway, API key, Worker runtime, model route, or container set;
- mount the host repository into a container;
- restart or recreate a Worker without separate approval;
- delete task, Matrix, MinIO, or model-usage evidence.

Those orchestration and gate claims remain P10-4 work. P9 remains the stable
local fallback throughout P10-3.

## 3. Role and Skill boundary

| Worker | Assigned custom Skill | Allowed output | Forbidden responsibility |
|---|---|---|---|
| `cs-diff-analyzer` | `codesentinel-diff-review` | Structured change intent and affected-symbol facts | Security, quality, or gate decision |
| `cs-security-scanner` | `codesentinel-security-review` | Semantic security findings linked to trusted scan evidence | Gate decision or secret reconstruction |
| `cs-quality-reviewer` | `codesentinel-quality-review` | Correctness, reliability, maintainability, and performance findings | Security or gate decision |

Each Worker receives exactly one role Skill. No cross-role Skill is installed.
The existing Worker SOUL remains authoritative; a Skill sharpens the procedure
and output contract but does not broaden the role.

Each Skill package must contain:

- `SKILL.md` with `name`, `description`, and `assign_when` front matter;
- a role manifest with role, schema, prompt, runtime, source commit, and bundle
  hash;
- bounded input/output references and one small valid example;
- scripts invoked explicitly with `bash`, because object storage does not
  guarantee preservation of executable permission bits;
- no credential, target-repository path, raw patch, Provider, or model client.

## 4. Authoritative delivery design

The model must not construct the complete delivery envelope or assign its own
hash and evidence level. The safe flow is:

1. the Worker acknowledges the registered finite task through `taskflow`;
2. it pulls and verifies the cloud-safe input references and runtime bundle;
3. it analyzes only the bounded role context and writes a role payload;
4. the deterministic runtime validates the expected role, agent, review,
   schema, evidence lineage, and paths;
5. the runtime computes canonical JSON and SHA-256 values and atomically writes
   `workspace/delivery.json`;
6. the Worker submits through `taskflow` and names `delivery.json` as a
   deliverable;
7. the Manager pulls and independently validates the result.

`workspace/delivery.json` is authoritative. Matrix messages and `result.md`
may reference it but cannot replace it. A chat-only completion is a failure.

The runtime extension must remain dependency-light. It may depend on Pydantic
and pure role contracts, but it must not include the DeepSeek client, Provider
stack, deterministic scanner implementation, `.env`, or credentials. LLM
claims remain E0/E1; E2/E3 may only come from deterministic or independently
verified evidence.

## 5. Official AgentTeams protocol controls

Deployment must use the Manager's official skill-management script with the
exact Worker and Skill name. `--no-notify` is mandatory so Skill synchronization
does not trigger an unnecessary model turn.

Every live validation task must follow the finite-task protocol:

- create `shared/tasks/{task-id}/meta.json` and `spec.md`;
- publish the task artifacts before sending control information;
- register it with `manage-state.sh --action add-finite` before waiting;
- send the complete assignment to the Worker's own room;
- require `taskflow(action="ack_task")` before work;
- require `taskflow(action="submit_task")` for the final result;
- pull, validate, record completion, and then remove it from active state.

The official prose and the installed `push-worker-skills.sh` disagree on
removal behavior. The installed script actually deletes the exact Skill path
from MinIO while updating the registry. Therefore removal is destructive for
that Skill version and may only occur after an exact backup and target check.

## 6. Model-call budget

The frozen limits are interpreted as two independently enforced counters:

- `domain_analysis_count <= 4`: normally three role analyses plus at most one
  shared targeted repair;
- `provider_call_count_delta <= 8`: the actual CoPaw token-usage `call_count`
  increase across all affected Workers.

This interpretation does not relax the budget. A single semantic task may use
more than one provider request during tool loops, so both counters are needed.

P10-3 uses zero Manager model calls. Before and after every Worker task, the
Worker's structured token-usage file is snapshotted and the exact delta is
recorded. Stop immediately when either limit would be exceeded. If the first
Worker consumes more than two provider calls for one ordinary task, stop before
deploying to the next role and review the Skill/task design.

One repair is allowed only when both the fourth domain-analysis slot and enough
provider-call budget remain. There is no automatic retry.

## 7. Staged implementation plan

### P10-3A — offline implementation, zero model calls

1. Add pure role-payload contracts and a deterministic delivery builder/CLI.
2. Add the three versioned Skill packages and their manifests, references, and
   minimal examples.
3. Add positive and fail-closed fixtures for all roles.
4. Verify wrong-role, wrong-schema, wrong-review, unsafe-path, invalid-hash,
   cross-lineage, E2/E3 overclaim, and partial-write rejection.
5. Rebuild twice and verify a byte-identical allow-listed runtime bundle.
6. Run the full unit suite, Ruff, `pip check`, `git diff --check`, and secret
   scanning.
7. Stop for user review. Do not deploy.
8. Only after separate approval, create and push the P10-3A baseline commit.

### P10-3B — deployment from the accepted clean commit

1. Rebuild the bundle and require `source_dirty=false` and the accepted commit.
2. Snapshot registry/state, room IDs, model routes, call counts, existing Skill
   paths, and all relevant hashes.
3. Deploy and validate `codesentinel-diff-review` on `cs-diff-analyzer`.
4. Stop and inspect its taskflow result, delivery, hashes, and call-count delta.
5. If accepted, repeat for Security; stop and inspect again.
6. If accepted, repeat for Quality; stop and inspect again.
7. Pull and validate all three results and preserve the evidence manifest.
8. Remove only temporary Manager-side staging, then verify model routes,
   AgentTeams containers, Dify stopped state, Git state, and P9 fallback.

Workers are deliberately validated sequentially in P10-3. Parallel dispatch is
an independent claim and belongs to P10-4.

## 8. Acceptance criteria

P10-3 passes only when all of the following are true:

- the deployed bundle identifies the accepted commit and
  `source_dirty=false`;
- each role Skill exists only on its intended Worker;
- repository, MinIO, and Worker copies have identical recorded hashes;
- three finite tasks are registered, acknowledged, and submitted via
  `taskflow`;
- every task has a strict `workspace/delivery.json` and a result that references
  it;
- independent validation rejects cross-role, cross-review, schema, path, hash,
  and evidence-lineage violations;
- normal domain analyses equal three and never exceed four;
- aggregate provider call-count delta never exceeds eight;
- Manager model-call delta is zero;
- Worker routes remain `hiclaw-gateway/deepseek-v4-pro`;
- the five AgentTeams containers remain healthy and Dify remains stopped;
- P9 regression tests and the complete repository quality checks pass;
- no final-gate, concurrency, or autonomous-Manager claim is made.

Any missing item yields **P10-3 not accepted**, even if Worker chat responses
look correct.

## 9. Rollback plan

### Before each deployment

- record the exact Git commit, clean bundle hash, Skill-package hash, registry
  and state hash, Worker room ID, route, call count, and remote Skill listing;
- copy the previous exact Skill version if one exists;
- verify the target Worker and exact target Skill name before mutation.

### Skill deployment failure

1. preserve the failed package, logs, registry snapshot, and hashes;
2. remove only the exact affected Skill using the official script with
   `--no-notify`, after confirming its backup;
3. remove only the matching Worker-local Skill cache, if created and verified;
4. restore the prior registry/Skill version when applicable;
5. remove only the temporary Manager staging path;
6. verify the other Workers, routes, containers, Dify state, and P9 fallback.

### Task or model failure

- preserve the task directory, `result.md`, delivery candidate, Matrix event
  references, logs, and usage snapshots;
- record failure before clearing only its active Manager task state;
- do not delete shared or Matrix evidence;
- do not retry unless the one shared repair slot and provider budget permit it;
- on wrong role, chat-only output, or invalid schema, use at most one targeted
  repair task; otherwise stop;
- on a route/model change, stop and roll back only the affected Skill;
- if dynamic Skill discovery fails, stop for review rather than restarting.

P10-3 rollback never runs `docker compose down`, recreates a Worker, changes a
gateway/key, deletes a volume, resets Git, or removes review history. Any
Worker restart requires separate user approval.

## 10. Hard stop conditions

Stop the current slice and report without proceeding to another Worker when:

- Git is dirty at deployment build time or the source commit/hash differs;
- a secret, raw credential value, absolute host path, or unsafe patch reaches
  Matrix/MinIO;
- an artifact hash, schema, role, review, task, or agent identity check fails;
- the Worker submits chat text without the authoritative delivery;
- a Skill appears on the wrong Worker;
- a route/runtime/container changes unexpectedly;
- the model budget is reached or cannot be measured reliably;
- rollback cannot identify one exact target safely.

## 11. Approval gates and recommended next action

This plan review, P10-3A implementation, R1/R2 remediation, Gate A, and the
Diff Worker canary are complete. P10-3B remains incomplete because Security,
Quality, and evidence closure have not run.

The post-R1 execution gates, exact clean-baseline rule, staged Worker canaries,
acceptance criteria, and rollback matrix are frozen in
[`P10-3B-controlled-deployment-plan.md`](P10-3B-controlled-deployment-plan.md).
The Diff completion evidence must be independently reviewed, committed, and
pushed before a separate Gate C decision. Security deployment must not begin
under the completed Diff-only approval.
