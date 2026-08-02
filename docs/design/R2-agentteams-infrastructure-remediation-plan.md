# R2 AgentTeams infrastructure remediation plan

Date: 2026-08-02

Plan review result: **CONDITIONAL GO**

Execution status: **PLAN ONLY; no infrastructure mutation is authorized**

This plan remediates the two infrastructure blockers observed during the first
P10-3B Diff Worker canary attempt. It does not retry that canary, deploy
Security or Quality, create a finite task, send a Matrix assignment, or call a
model.

## 1. Objective and success definition

R2 succeeds only when all of the following are demonstrated without a model
call:

1. an official AgentTeams Skill push cannot be accepted from exit code or log
   text alone;
2. the Manager can access only the approved Diff Skill object prefix needed
   for deployment and exact rollback;
3. repository, staging, remote, and Diff Worker-local package hashes and file
   allow-lists can be compared independently;
4. an upload failure, partial upload, unexpected object, registry mismatch, or
   rollback failure is detected and fails closed;
5. Manager Heartbeat is paused through the supported CoPaw API for a bounded
   maintenance window, the Manager usage counter is proven quiescent, and the
   exact Heartbeat settings are restored on every exit path;
6. a zero-model Diff deployment/synchronization probe can be completely and
   recoverably rolled back;
7. Security, Quality, Dify, routes, credentials, containers, volumes, tasks,
   and Matrix history remain outside the mutation scope.

Passing R2 only repairs the deployment infrastructure. It does not satisfy the
P10-3B Diff Canary acceptance criterion, because no Worker semantic delivery
is produced in R2.

## 2. Evidence basis

The plan is based on the accepted source baseline
`ffe1ecf824556343859344f8570f928eb628b7c6` and the uncommitted first-attempt
report.

### 2.1 Official deployment behavior

The installed AgentTeams v1.1.2
`push-worker-skills.sh` has SHA-256:

`71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c`

The read-only source audit confirmed:

- line 14 uses `set -e`, not `set -euo pipefail`;
- lines 122-123 and 138-139 pipe `mc mirror` into `tail -3`;
- `--add-skill` changes the in-memory registry before upload;
- the registry is persisted after the upload function reports success;
- `--remove-skill` persists the registry before `mc rm` and converts a missing
  assignment to an empty list;
- removal logs an `mc rm` failure but still exits successfully.

Therefore neither the add nor removal path is a transaction, and neither exit
code alone proves remote state.

### 2.2 Current MinIO policy shape

Each Worker has a dedicated policy that permits `ListBucket` only for its own
`agents/<worker>` and `shared` prefixes, and permits object get/put/delete only
under those prefixes. The Manager's current storage identity was denied access
to the Diff Skill prefix during the live attempt.

Using the built-in `readwrite` policy would grant `s3:*` on every bucket and is
explicitly rejected. R2 uses a new CodeSentinel-specific policy limited to one
Worker and one Skill prefix.

### 2.3 Manager background model activity

The active Manager Agent reports:

```json
{"enabled": true, "every": "30m", "target": "main", "activeHours": null}
```

CoPaw schedules the Heartbeat every 30 minutes and runs `HEARTBEAT.md` as an
agent request. One Heartbeat can therefore consume multiple provider calls
during tool loops. Its execution timeout is 120 seconds.

The supported local API is:

`GET/PUT /api/agents/default/config/heartbeat`

The PUT implementation saves the Agent configuration and hot-reschedules or
removes the `_heartbeat` scheduler job. No container restart is required.

## 3. Frozen design decisions

### 3.1 Do not patch the running vendor image

R2 will not edit `/opt/hiclaw` or CoPaw package files in place. A project-owned
deployment guard will invoke the pinned official script, treat its result as
untrusted evidence, and independently verify the resulting state.

This keeps the AgentTeams installation upgradeable and makes the workaround
reviewable, testable, and reproducible in the CodeSentinel repository.

### 3.2 Use a host-side transactional guard

The planned implementation lives under:

- `deploy/agentteams/operations/guarded_skill_deploy.py`;
- `tests/agentteams/test_guarded_skill_deploy.py`;
- `docs/runbooks/agentteams-skill-deployment.md`.

The guard orchestrates existing Docker/AgentTeams commands but never reads,
prints, serializes, or accepts an API key, MinIO secret key, Matrix token, or
gateway credential as a CLI argument.

For its first version, the only allowed mapping is:

`cs-diff-analyzer -> codesentinel-diff-review`

Security and Quality mappings are not added until their existing P10 gates are
separately approved.

The guard must:

1. require a clean, accepted Git revision and pinned official-script hash;
2. require the exact nine-file package allow-list and accepted runtime binding;
3. snapshot the registry, task state, exact remote prefix, local Worker path,
   routes, usage counters, and relevant hashes;
4. invoke the official script with the exact Worker, exact Skill, and
   `--no-notify`;
5. reject non-zero exit, `Access Denied`, `Insufficient permissions`, `0 B`,
   missing objects, unexpected objects, partial readback, or any hash mismatch;
6. require all nine remote objects to match the staged package by relative
   POSIX path and SHA-256;
7. require the registry assignment only after remote verification succeeds;
8. use the Diff Worker's own identity for an independent remote readback;
9. verify the Worker-local copy after the official `hiclaw-sync` pull;
10. execute a single exact rollback path and verify its postconditions;
11. preserve evidence and stop if any rollback target cannot be proven.

The guard must never interpret a convincing log line as authoritative state.

### 3.3 Grant only a Diff-specific MinIO capability

The proposed policy name is:

`codesentinel-manager-diff-deployer-v1`

The exact policy template is:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::hiclaw-storage"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::hiclaw-storage"],
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "agents/cs-diff-analyzer/skills/codesentinel-diff-review",
            "agents/cs-diff-analyzer/skills/codesentinel-diff-review/*"
          ]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": [
        "arn:aws:s3:::hiclaw-storage/agents/cs-diff-analyzer/skills/codesentinel-diff-review/*"
      ]
    }
  ]
}
```

The policy is attached only to the existing Manager storage identity. The
identity is passed between local processes without being printed; evidence
records only a one-way identity fingerprint, policy name, policy hash, and
attachment result.

The policy deliberately excludes:

- every Security and Quality prefix;
- sibling Diff Skills;
- `shared/`, task, review, Matrix, gateway, and secret paths;
- bucket administration, user administration, and policy administration;
- every wildcard resource broader than the one approved Skill prefix.

### 3.4 Pause Heartbeat through the supported API

R2 will not stop or restart the Manager container and will not edit
`agent.json` directly.

At the beginning of the bounded maintenance window, the operator must:

1. GET and preserve the complete Heartbeat JSON and its canonical hash;
2. PUT the same configuration with only `enabled=false`;
3. GET it back and require `enabled=false`;
4. require a new scheduler log entry confirming the Heartbeat job was removed;
5. take Manager usage snapshots at `t0`, `t0+65s`, and `t0+130s` and require
   identical DeepSeek `call_count` values;
6. abort if another Matrix/admin operation is pending or the counter changes.

The 130-second quiet period exceeds the Heartbeat execution timeout and drains
an already-running Heartbeat before R2 mutation begins.

The maintenance window is limited to 20 minutes. A `finally`/trap path must PUT
the exact original Heartbeat JSON back and verify the GET response even when a
policy, upload, verification, or rollback step fails.

## 4. Staged execution plan

### R2-0: documentation baseline

Scope: documentation only.

1. Review this plan and the first Canary attempt report.
2. Commit them with the documentation index, explicitly excluding
   `docs/audits/`.
3. Push the accepted documentation commit.
4. Require local `HEAD == origin/main` before R2-1 starts.

Acceptance: clean accepted baseline, no infrastructure change, no model call.

Approval: a separate commit and push approval is required.

### R2-1: offline transactional guard implementation

Scope: repository code and tests only.

1. Implement the allow-listed deployment guard and evidence schema.
2. Parse command results as structured records; redact credential-shaped
   fields before persistence.
3. Model registry comparison semantically so AgentTeams-managed timestamps do
   not hide assignment changes.
4. Add deterministic tests for:

   - official exit zero with `Access Denied` output;
   - official exit zero with `0 B` and no remote object;
   - partial nine-file upload;
   - unexpected tenth object;
   - remote/staging hash mismatch;
   - registry changed before verified upload;
   - exact cleanup failure;
   - pre-existing target with no verified backup;
   - wrong Worker/Skill mapping;
   - secret-shaped output redaction;
   - Heartbeat restore on every failure path.

5. Run the focused tests, complete suite, Ruff, compile check, `pip check`,
   `git diff --check`, and secret scan.
6. Stop for review; do not create a policy or touch a Worker.

Acceptance: all fault-injection tests pass and no Docker, MinIO, CoPaw, Matrix,
route, model, or Worker state changes.

Approval: R2-1 implementation and its later commit/push each require separate
approval.

### R2-2: live read-only preflight

Scope: external read-only evidence.

1. Require the accepted R2-1 commit to be pushed and the working tree clean
   except for the excluded health audit.
2. Verify the five expected AgentTeams containers and Dify stopped state.
3. Re-read the official script hash and Heartbeat API behavior.
4. Snapshot policy names/hashes/attachments without secret values.
5. Require the Diff Skill target to be absent remotely and locally.
6. Require zero active finite tasks and unchanged Worker call counters.
7. Snapshot the current Manager Heartbeat configuration and usage counter.

Acceptance: no mutation and every exact rollback target is known.

### R2-3: bounded Manager quiescence window

Scope: temporary Heartbeat configuration only.

1. Disable Heartbeat through the official PUT endpoint.
2. Verify hot-removal and the 130-second stable usage interval.
3. Install the unconditional Heartbeat restoration trap before any MinIO
   policy mutation.
4. Record the start and expiry time of the 20-minute window.

Acceptance: Manager DeepSeek counter remains stable and exact restoration is
already armed. Otherwise restore immediately and stop.

### R2-4: Diff-only least-privilege policy probe

Scope: one new policy, one attachment, and one disposable object under the
approved Diff Skill prefix.

1. Create the exact reviewed policy and verify its canonical SHA-256.
2. Attach it only to the existing Manager storage identity without printing
   that identity or either credential.
3. Upload a nonce-bound, non-secret probe object beneath
   `codesentinel-diff-review/.codesentinel-r2-probe/`.
4. Require Manager put/list/get, Diff Worker get, and Manager exact delete to
   succeed with matching hashes.
5. Require the probe to be absent after deletion.
6. Require Manager access attempts against the Security Skill prefix, Quality
   Skill prefix, and a sibling Diff Skill prefix to fail.
7. Recheck Security and Quality usage, local Skill paths, and registries.

Acceptance: all positive operations succeed only inside the approved prefix;
all negative authorization tests fail; no probe object remains; no model call
occurs.

If any test fails, detach the exact policy, delete it only after verifying no
other attachment, restore Heartbeat, and stop.

### R2-5: zero-model deployment transaction and rollback proof

Scope: Diff Skill only; no finite task or Matrix event.

1. Re-materialize the Diff package from the accepted clean revision and verify
   its nine-file allow-list, runtime binding, and tree hash.
2. Require the exact remote and local target to be absent.
3. Run the guarded official `--add-skill --no-notify` transaction.
4. Verify the exact remote allow-list and per-file hashes twice: once through
   the Manager identity and once through the Diff Worker identity.
5. Run the installed official `hiclaw-sync` deterministically inside only the
   Diff Worker; do not ask the Worker model to perform it.
6. Verify the local Diff package allow-list and hashes, registry assignment,
   routes, task state, and unchanged usage counters.
7. Exercise the guarded rollback:

   - move the exact verified local Skill directory to the revision-scoped
     backup instead of deleting it;
   - invoke the exact official removal path;
   - independently verify remote absence;
   - restore the pre-attempt registry semantics from backup;
   - verify central source absence and preserve all failure/success evidence.

8. Recheck that no Security/Quality Skill, task, Matrix event, route, model
   call, container, Dify state, or unrelated Git file changed.

Acceptance: complete deploy/read/sync/rollback evidence, Manager and all Worker
usage counters unchanged, all targets returned to the pre-probe semantics, and
the minimal Diff policy remains the only persistent infrastructure addition.

This slice proves the infrastructure path only. It intentionally leaves the
Diff Skill undeployed so the later P10 Canary begins from a known baseline.

### R2-6: evidence closure

1. Restore the exact original Heartbeat settings through the PUT endpoint.
2. Require a matching GET response and scheduler reschedule evidence.
3. Record before/after policy, registry, task, route, usage, object, local path,
   container, Dify, and Git state.
4. Produce a machine-readable evidence manifest without credential values.
5. Produce a human-readable R2 execution report.
6. Stop for review; do not retry the Diff Worker Canary.

Acceptance: Heartbeat restored, only the reviewed Diff policy remains, no
Skill remains deployed, no model budget used, and all evidence is reproducible.

## 5. Approval gates

R2 is intentionally split so no broad approval is implied.

| Gate | User approval | Authorized scope |
|---|---|---|
| R2-A | Plan/report commit and push | Documentation only |
| R2-B | Execute R2-1 | Offline guard code and tests only |
| R2-C | Commit and push R2-1 | Accepted offline implementation only |
| R2-D | Execute R2-2 and R2-3 | Read-only preflight plus temporary Heartbeat pause |
| R2-E | Execute R2-4 | Exact Diff policy and capability probe only |
| R2-F | Execute R2-5 and R2-6 | Zero-model Diff transaction, rollback, and closure |
| R2-G | Commit and push R2 evidence | Reviewed evidence only |

None of these gates authorizes a semantic Diff task, Security, Quality, a
container restart, a gateway/key change, or a P10-3B retry.

## 6. Rollback matrix

| Trigger | Exact response | Required evidence |
|---|---|---|
| Heartbeat cannot be disabled or counter is not stable | Restore original Heartbeat JSON and stop before policy mutation | GET responses, scheduler log, counter snapshots |
| Policy hash/attachment target is ambiguous | Make no policy change; restore Heartbeat and stop | Policy inventory and identity fingerprint |
| Capability probe exceeds exact Diff prefix | Delete only a proven probe object, detach/delete exact policy, restore Heartbeat | Positive/negative authorization results |
| Official add reports false success or partial upload | Reject transaction, remove only proven uploaded objects, restore registry preimage | Raw redacted output, object allow-list, hashes |
| Worker sync produces wrong or extra Skill files | Quarantine only the exact CodeSentinel Skill path; reject R2 | Before/after local tree manifests |
| Exact remote or local rollback cannot be proven | Perform no broader deletion or restart; preserve evidence and stop | Unresolved object/path evidence |
| Manager or Worker usage changes | Restore Skill/registry/policy as applicable, restore Heartbeat, stop | All before/after usage snapshots |
| Security/Quality, route, Dify, container, or credential boundary changes | Stop immediately; revert only the exact R2 mutations | Topology, route, policy, and path evidence |

No rollback may use `docker compose down`, recreate a container, reset Git,
delete a volume, use a wildcard Worker path, grant `readwrite`, edit an API key,
delete Matrix/task history, or erase the first Canary attempt evidence.

## 7. Hard-stop conditions

R2 stops immediately if:

- the accepted Git revision or official-script hash changes;
- the policy or attachment subject cannot be identified without exposing a
  credential;
- a positive capability is missing or a negative authorization succeeds;
- Heartbeat API hot-reload cannot be independently verified;
- Manager usage changes after the quiet window begins;
- any model, finite task, Matrix event, Security Skill, or Quality Skill is
  required to complete R2;
- a remote/local file is missing, extra, mismatched, or outside the exact
  allow-list;
- the guard cannot identify one exact recoverable rollback target;
- the 20-minute maintenance window expires before Heartbeat restoration.

## 8. Evidence required for approval

The R2 execution report must include:

- accepted Git revision and `HEAD == origin/main` proof;
- official script and CoPaw Heartbeat implementation hashes;
- canonical policy JSON hash and redacted attachment result;
- positive and negative capability-test matrix;
- pre/staged/remote/Worker-local package manifests and tree hashes;
- official script output with secret redaction;
- registry semantic diff and active-task count;
- Heartbeat GET/PUT/GET and restoration evidence;
- timestamped Manager and Worker call-count snapshots;
- rollback targets and post-rollback absence proofs;
- routes, containers, Dify, Git, Security, and Quality preservation checks.

Evidence must never contain an access key, secret key, Matrix token, gateway
key, API key, authorization header, or raw secret finding.

## 9. Strict plan audit

### Correctness

**PASS, conditional on implementation tests.** The plan addresses both known
root causes instead of retrying the same deployment. Post-state verification,
not vendor output, becomes authoritative. The fault-injection test list covers
the exact false-success and partial-state failures already observed.

### Least privilege and rollback safety

**PASS.** The proposed policy is limited to one Worker and one Skill, includes
negative authorization tests, and rejects the global `readwrite` policy. Every
destructive action is exact-targeted and preceded by a backup/hash check. Local
Skill cleanup is recoverable by quarantine rather than immediate deletion.

### Model-budget integrity

**PASS for R2 itself, with a residual P10 risk.** The official Heartbeat API and
130-second quiet window can make R2's zero-call claim measurable. R2 creates no
Matrix event or finite task. The later semantic Canary must still prove that a
Worker completion message does not independently trigger a Manager model turn;
R2 does not silently reinterpret the frozen `Manager delta == 0` invariant.

Before a P10-3B retry, R2-1 must include a read-only audit of the Manager Matrix
inbound trigger path. If zero-call behavior cannot be proven from code and
existing evidence, a separately budgeted diagnostic or a reviewed P10 contract
amendment is required. Neither is authorized by this plan.

### Operational feasibility

**PASS.** The required primitives are present: MinIO policy administration in
the Controller, exact per-Worker policies, the pinned official push script,
the Diff Worker's official `hiclaw-sync`, CoPaw's Heartbeat GET/PUT API, and
hot scheduler rescheduling. No image rebuild or container restart is necessary.

### Competition value

**PASS.** R2 strengthens CodeSentinel's defensible claims around least
privilege, fail-closed orchestration, deterministic artifact lineage,
transactional deployment, rollback, and observability. These controls are more
valuable to the competition submission than hiding the failed Canary or using
an untracked `docker cp` workaround.

### Residual risks

1. The AgentTeams v1.1.2 vendor script remains defective; all CodeSentinel
   deployments must go through the pinned guard until an upstream fix is
   independently audited.
2. Heartbeat PUT returns before asynchronous rescheduling completes; the log
   and 130-second stability gates are mandatory.
3. MinIO policy mutation is persistent external state and requires explicit
   approval, exact attachment evidence, and an available detach/delete path.
4. `hiclaw-sync` mirrors more than one Skill and does not remove stale local
   files; the guard must compare all affected Diff Worker paths and quarantine
   only the exact verified CodeSentinel directory during rollback.
5. The later Worker-to-Manager Matrix path may consume Manager calls; the P10
   Canary remains NO-GO until that risk is closed or the contract is explicitly
   amended.

## 10. Audit decision and next action

R2 is **GO for a documentation-only baseline and for later offline guard
implementation**. It is **NO-GO for live policy mutation, Heartbeat pause, or
deployment probing** until:

1. this plan and the first-attempt report are reviewed, committed, and pushed;
2. R2-1 is separately approved, implemented, and passes its full offline
   fault-injection gate;
3. the user separately approves R2-D, R2-E, and R2-F in order.

After R2 completes and its evidence commit is accepted, Gate B must run a new
zero-model predeployment refresh from that final clean commit. Only then may
the user consider approving a second Diff Worker Canary.
