# P10-3B Diff Worker canary attempt 1

Date: 2026-08-02

Result: **BLOCKED before task dispatch; fail-closed rollback completed**

Source baseline: `ffe1ecf824556343859344f8570f928eb628b7c6`

This report records the first approved Diff-only live deployment attempt. It
does not claim that the Diff Skill was installed or that a Worker delivery was
produced. Security and Quality were outside the approved scope and were not
executed.

## Approved boundaries

- deploy only `codesentinel-diff-review` to `cs-diff-analyzer`;
- run at most one Diff domain analysis;
- allow at most two Diff Worker provider calls;
- require zero Manager model-call delta;
- stop before Security and Quality under every outcome;
- hard-stop before task dispatch if package identity, remote readback, route,
  budget, secret, or rollback evidence is ambiguous.

## What completed

1. Snapshotted the Manager registry and finite-task state, all role usage
   counters, routes, the exact Diff Skill target, and the accepted staging
   inputs.
2. Created a recoverable Manager-side backup at:
   `/root/manager-workspace/codesentinel-backups/p10-3b-diff-canary-ffe1ecf824556343859344f8570f928eb628b7c6`.
3. Uploaded the clean runtime bundle and external manifest to the unique
   revision-scoped shared runtime path. Exact readback produced:

   - bundle SHA-256:
     `0c6b08bb7921a3ffddb1b532f38a8a620b264d2d39cf83e29031fbbb4e2c9bed`;
   - external-manifest SHA-256:
     `7826db6c67124f04383b5f111d760f8dc4bf7c84a640adf8af22bf1332a28c06`.

4. Revalidated the nine-file Diff package between accepted staging and the
   temporary Manager source. Its sorted POSIX-path/per-file-hash tree digest
   was:
   `a0f370e51713959df5da5c2c516f1e4af4c8f1a3301a9237f4ec8044e819c6dd`.
5. Invoked the official `push-worker-skills.sh` with the exact Worker, exact
   Skill, and `--no-notify`.
6. Stopped before finite-task registration, artifact publication, Matrix
   assignment, task acknowledgement, or any Worker analysis when exact remote
   readback failed.

The revision-scoped shared runtime objects remain preserved as immutable
attempt evidence. No Worker references them.

## Hard blocker 1: official Skill deployment was a false success

The installed AgentTeams v1.1.2 script begins with `set -e` but does not enable
`pipefail`. Its upload path pipes `mc mirror` output into `tail -3`. During this
attempt MinIO denied the directory comparison/list operation, but the pipeline
continued and the script updated the registry and printed a success message.
It reported `0 B` transferred.

Independent checks disproved the success claim:

- exact readback with the Diff Worker identity returned `Object does not
  exist` for the deployed `SKILL.md`;
- an exact-object `mc cp` with the Manager identity returned `Insufficient
  permissions` for the Worker Skill prefix;
- the Diff Worker-visible local Skill path remained absent.

Therefore the official script's exit/success message is not sufficient
deployment evidence in the current MinIO policy. Continuing to task dispatch
would have violated the approved hash and remote-readback gate.

## Hard blocker 2: Manager zero-call attribution is unavailable

The Manager's 2026-08-02 DeepSeek `call_count` changed from `10` to `14` during
the observation window, even though this procedure created no finite task,
sent no Matrix assignment, and invoked no Manager model request. The activity
is consistent with independent Manager background processing, but the exact
cause was not proven.

This means the required `Manager model-call delta == 0` cannot currently be
attributed or demonstrated from the aggregate daily counter. It is a hard
evidence blocker even though it did not consume the Diff Worker budget.

## Rollback and final state

The rollback used the official exact-Skill removal path, then restored the
registry from the pre-attempt backup. AgentTeams subsequently refreshed only
the registry timestamps. Semantic comparison showed that the three Worker
entries and their assignments were restored, with all three `skills` values
equal to `None`.

| Check | Final result |
|---|---|
| Manager finite tasks | `active_tasks` length `0`; state hash equals the pre-attempt backup |
| Central Manager Diff Skill source | Absent; failed package preserved under the backup root |
| Remote Diff Skill object | Absent by exact Diff Worker identity readback |
| Diff Worker local Skill | Absent |
| Diff Worker usage | Hash unchanged; domain analyses `0`, provider-call delta `0` |
| Security Worker | Usage hash unchanged; no CodeSentinel Skill |
| Quality Worker | Usage hash unchanged; no CodeSentinel Skill |
| Active routes | Manager, Diff, Security, and Quality remain on `hiclaw-gateway/deepseek-v4-pro` |
| Containers | Only the five expected AgentTeams containers are running; Dify remains stopped |
| Git baseline | `HEAD == origin/main == ffe1ecf`; no tracked source change before this report |

Managed CoPaw configuration files were reserialized in the background during
the observation window, including on untouched Workers. The active provider
and model were re-read semantically rather than accepted by file hash alone.

## Budget disposition

- Diff domain analyses used: `0 / 1`;
- Diff Worker provider calls used: `0 / 2`;
- Security and Quality analyses/calls used: `0`;
- Manager aggregate counter delta observed: `+4`, not attributable to this
  canary and therefore not acceptable as zero-call proof.

The task budget was preserved, but the Canary acceptance criteria were not met
because no independently validated Worker delivery exists.

## Gate decision

P10-3B Gate B remains **NO-GO**. This attempt must not be represented as a
successful Diff Worker canary.

Before any retry, a separately reviewed infrastructure-remediation plan must:

1. grant the Manager's official deployment identity the minimum exact-object
   permissions needed for only the intended Worker Skill prefix, or provide an
   official controller-mediated distribution path;
2. make the deployment wrapper fail reliably (`pipefail` or equivalent) and
   require exact post-upload readback/hash verification before registry
   success is accepted;
3. isolate, disable, or task-correlate Manager background model usage so the
   zero-call invariant is measurable;
4. repeat a zero-model read-only preflight before authorizing another Diff
   canary.

Direct `docker cp`, manual Worker-volume injection, container recreation, route
changes, broad MinIO permissions, and silent relaxation of the Manager budget
are not acceptable workarounds. They would weaken both the security posture
and the competition claim that CodeSentinel uses a controlled, auditable
AgentTeams workflow.
