# AgentTeams guarded Skill deployment runbook

Status: **R2-1 offline implementation only**

The R2-1 guard is a fail-closed transaction state machine. Its current public
entry point cannot call Docker, MinIO, Matrix, CoPaw, or a model. A concrete
live backend remains unavailable until the separately approved R2-D, R2-E, and
R2-F gates.

## Offline checks

Run the guard self-check:

```powershell
& "D:\python\Anaconda\envs\agent_dev\python.exe" `
  deploy\agentteams\operations\guarded_skill_deploy.py self-check
```

The JSON response must report:

- `ok=true`;
- `model_calls=0`;
- `live_execution_available=false`;
- only `cs-diff-analyzer -> codesentinel-diff-review`;
- official script SHA-256
  `71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c`.

Inspect one already materialized nine-file staging package:

```powershell
& "D:\python\Anaconda\envs\agent_dev\python.exe" `
  deploy\agentteams\operations\guarded_skill_deploy.py inspect-package `
  --package-root "<materialized-diff-package>"
```

The source template is deliberately rejected because it does not contain a
bound `deployment-manifest.json`. Only a clean, revision-bound staging package
may pass.

## Authoritative state

The guard never trusts an official script exit code or success log by itself.
An accepted transaction requires all of the following:

1. pinned source revision and official script hash;
2. exact nine-file staging allow-list;
3. Manager and Diff Worker remote readbacks matching staging by path and hash;
4. the exact registry assignment and no unrelated semantic change;
5. Diff Worker-local readback after the official sync;
6. unchanged routes, active-task count, and all role usage counters;
7. complete remote/local/registry rollback proof;
8. exact Heartbeat restoration in an unconditional finalization path.

Registry `updated_at` and per-Worker `skills_updated_at` are treated as managed
timestamps. They are excluded from semantic comparison; Skill assignments are
never normalized away.

## Failure handling

The state machine rejects:

- non-zero command status;
- `Access Denied`, `Insufficient permissions`, missing-object, or equivalent
  failure output even when the command status is zero;
- a reported `0 B` official upload;
- missing, partial, extra, reordered, unsafe, or mismatched package evidence;
- wrong Worker/Skill identity;
- a pre-existing target without an approved versioned backup path;
- any route, task, usage, or registry change outside the transaction;
- any rollback or Heartbeat restoration that cannot be independently proven.

Command output is redacted before it may enter an error or evidence record.
Raw API keys, MinIO access/secret keys, Matrix tokens, authorization values,
and GitHub/OpenAI-style tokens must never be persisted.

## Matrix zero-call invariant

The AgentTeams `v1.1.2` CoPaw source was audited at tag commit
`a99457830fafb99c991bdb666aa8a1eef2f83b12`.

- Ordinary allowed Matrix messages that mention the Manager are converted to
  an Agent request and enqueued. They can consume a Manager model call.
- A targeted readiness probe and `NO_REPLY` are handled without the model.
- `taskflow submit_task` writes and verifies the shared task result; it does
  not send a Matrix completion message itself.
- The message tool adds `m.mentions` when the outgoing text contains an
  explicit Matrix user ID.

Therefore a zero-Manager-call deployment probe or Worker canary must never put
the Manager MXID in a Worker completion message. The authoritative result is
the verified `workspace/delivery.json`, polled by the approved host-side
controller. Any Manager mention, unexpected Matrix event, or Manager usage
increment is a hard stop. This rule is for the bounded canary only and does not
claim that the later Manager-orchestrated P10 workflow is complete.

## Live boundary

Do not add or invoke a live backend merely because the offline tests pass.
Before live activation, the accepted R2 plan requires:

1. an accepted and pushed R2-1 implementation commit;
2. the R2-2 read-only preflight;
3. separate approval for the bounded Heartbeat pause;
4. separate approval for the exact Diff-only MinIO policy;
5. separate approval for the zero-model deployment and rollback probe.

The Diff-only policy gate uses two hashes. The immutable reviewed source must
match `a4ba569aea81bb06c1ea38c58d1cde6c25467513bf86a250ea27153ccbf6362f`.
MinIO readback may reorder only arrays containing exclusively strings and must
then match `02e7b1ccae93d69563f9a01b45bfd5929aa35fbcf3ac59b67ecec6abe695f148`
and the complete normalized source object. Statement order, duplicates,
actions, resources, conditions, prefixes, and fields remain exact fail-closed
boundaries.

Direct Worker `docker cp`, broad MinIO `readwrite`, vendor-image editing,
container restart/recreation, and any Security or Quality deployment remain
forbidden.

R2 completed the zero-model Diff deployment and rollback proof on 2026-08-02.
The approved operating baseline retains only
`codesentinel-manager-diff-deployer-v1`, requires the pinned official push and
sync script hashes, pauses Heartbeat for a new 130-second quiescence proof,
and accepts deployment only after Manager, Worker-remote, and Worker-local
nine-file hashes agree. A later semantic Canary remains a separate gate.
