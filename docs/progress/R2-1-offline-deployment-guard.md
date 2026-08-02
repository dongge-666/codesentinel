# R2-1 offline transactional deployment guard

Date: 2026-08-02

Result: **PASS after strict remediation and full offline regression**

Accepted baseline: `cc135c7abfe079a9adbb2c8f4385c62be1e2a8f3`

R2 overall status: **in progress; infrastructure blockers are not yet fixed**

This record covers repository code, tests, documentation, and a read-only
audit of pinned upstream source. It does not claim that MinIO permissions were
changed, Heartbeat was paused, a Worker Skill was deployed, or the Diff Canary
was retried.

## Scope completed

R2-1 added a project-owned, fail-closed transaction state machine for only:

`cs-diff-analyzer -> codesentinel-diff-review`

The state machine requires:

- the official deployment script SHA-256 to equal
  `71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c`;
- a clean Git-revision-bound deployment manifest and exact nine-file package;
- Manager-visible and Worker-visible remote readbacks matching staging by path
  and SHA-256;
- semantic registry equality while ignoring only AgentTeams-managed
  `updated_at` and per-Worker `skills_updated_at` fields;
- exact Worker-local readback after sync;
- unchanged task count, routes, and all four role usage counters;
- independent remote, local, and registry rollback proof;
- exact Heartbeat configuration and scheduler-state restoration on every exit
  path.

The module exposes live effects only through an injected protocol. No Docker,
MinIO, Matrix, CoPaw, HTTP, or model implementation exists in R2-1. The public
CLI supports only `self-check` and `inspect-package`; an `execute` action is
deliberately unavailable.

## Fault-injection guarantees

The offline backend tests reject and recover from:

- exit code zero accompanied by `Access Denied`;
- exit code zero accompanied by `0 B`;
- missing, partial, extra, or hash-mismatched remote packages;
- unrelated registry mutation;
- Worker sync failure or local hash mismatch;
- pre-existing remote or local targets;
- wrong Worker/Skill mapping or changed vendor script hash;
- stale source/runtime deployment binding;
- Heartbeat disable, scheduler removal, quiet-window, restore-command, and
  restore-runtime failures;
- route or model-usage drift, including drift after Heartbeat restoration;
- cleanup command failure or independently incomplete rollback;
- secret-shaped backend exceptions and command output;
- failure markers located beyond the persisted command-output truncation
  boundary.

Command evidence is redacted and bounded before persistence, while failure
detection examines the complete redacted output so truncation cannot create a
false success.

## Matrix inbound-trigger audit

The zero-Manager-call invariant was checked against the official AgentTeams
`v1.1.2` tag commit
[`a994578`](https://github.com/agentscope-ai/AgentTeams/tree/v1.1.2).

| Upstream source | Blob | Finding |
|---|---|---|
| [`copaw/src/matrix/channel.py`](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/copaw/src/matrix/channel.py) | `15ad07e01aed9fc9d9273fc8d9362a1f1d7a64bb` | An allowed ordinary group message that mentions the Manager is enqueued as an Agent request. `NO_REPLY` and targeted readiness probes bypass that path. |
| [`taskflow.py`](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/copaw/src/copaw_worker/hooks/tools/taskflow.py) | `4a9e35f146895ab59299c461cf30eee5c092637b` | `submit_task` writes, pushes, and verifies shared task state without sending a Matrix completion event. |
| [`message.py`](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/copaw/src/copaw_worker/hooks/tools/message.py) | `d6b41fcfbee93060e53cabe25dbdc77a6e8d0cca` | An explicit Matrix user ID in outgoing text is converted into visible and structured `m.mentions`. |
| [`agent.manager.json`](https://github.com/agentscope-ai/AgentTeams/blob/v1.1.2/copaw/src/copaw_worker/templates/agent.manager.json) | `19eb48d4a8bb237be5be06b625eada1a38a986d9` | The Manager Matrix profile requires group mentions by default. |

Conclusion: the bounded canary can retain `Manager call delta == 0` only when
the Worker completion contains no Manager MXID and the approved host-side
controller polls the authoritative `workspace/delivery.json`. A Manager
mention or usage increment is a hard stop. This does not establish the later
P10 Manager-orchestrated workflow; it closes only the canary attribution rule.

## Strict self-review and remediation

The first green implementation was not accepted on test count alone. A manual
code audit identified three latent false-pass or disclosure paths:

1. persisted command-output truncation could hide a failure marker located
   after the limit;
2. an arbitrary backend exception could surface credential-shaped text;
3. model usage could change after Heartbeat restoration but before final
   evidence creation.

The implementation now scans complete redacted output, normalizes unexpected
backend failures into redacted guard errors, verifies restored scheduler state,
and performs a final task/route/usage/Heartbeat preservation snapshot. Each
case has a dedicated regression test.

An initial manual CLI check also used the wrong option name (`--path` instead
of `--package-root`). The parser rejected it before inspection; no state was
changed. The command was corrected and the real Gate B staging package then
passed its exact nine-file and runtime-binding checks.

## Offline verification

| Check | Result |
|---|---|
| R2-1 focused fault-injection suite | 35 passed |
| R2-1 guard statement/branch coverage | 90% |
| AgentTeams test suite | 60 passed |
| Full repository test suite | 294 passed |
| Ruff over `src`, `tests`, and the offline operations entry point | PASS |
| Python compile check | PASS |
| `pip check` in `agent_dev` | No broken requirements |
| CLI `self-check` | PASS; live execution false, model calls 0 |
| Gate B materialized Diff package inspection | PASS; exact nine files and valid clean-runtime binding |
| Changed-scope secret scan | One code candidate; triaged as the pinned official script digest, not a credential |
| `git diff --check` | PASS |

## Preserved boundaries

- No Docker command was used by the R2-1 implementation or test path.
- No MinIO policy, object, registry, Worker path, or shared task changed.
- No Heartbeat, Matrix room, route, gateway, key, container, volume, Dify
  state, Security Skill, or Quality Skill changed.
- No Manager or Worker model call was made.
- No Git commit or push was created.
- The untracked `docs/audits/` report remained excluded and untouched.

## Remaining approval gate

R2-1 passing means the offline guard is ready for review. It does **not** mean
the original MinIO permission and vendor false-success problems are repaired
in the live environment.

The next safe sequence is:

1. user reviews this uncommitted R2-1 slice;
2. create and push an R2-1-only commit after separate approvals, excluding
   `docs/audits/`;
3. separately approve R2-2 live read-only preflight;
4. only after its evidence passes, consider the separately gated Heartbeat,
   least-privilege policy, and Diff-only zero-model deployment probe.
