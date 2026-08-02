# R2-2 live read-only infrastructure preflight

Date: 2026-08-02

Result: **PASS; GO only for separate R2-3 approval**

Accepted revision: `7f8b3a1589c00ba4fde182b13ed703692804f2bb`

R2 overall status: **in progress; no live mutation has been authorized or performed**

This record contains external read-only evidence. It does not authorize or
claim a Heartbeat pause, MinIO policy creation or attachment, object probe,
Skill deployment, Worker synchronization, Matrix event, finite task, or model
call.

## Baseline and topology

- local `HEAD` and `origin/main` both equal the accepted revision;
- the only working-tree exception is the excluded untracked
  `docs/audits/` report;
- exactly five expected AgentTeams `v1.1.2` containers are running: Controller,
  Manager, Diff, Security, and Quality;
- all 13 existing Dify containers are stopped;
- no container was started, stopped, restarted, recreated, or inspected for
  secret-bearing environment values.

## Official script and Heartbeat implementation

All four installed copies of `push-worker-skills.sh` have SHA-256:

`71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c`

The source still uses `set -e` and pipes both `mc mirror` paths into `tail`
without `pipefail`. Therefore the R2-1 guard must continue treating its exit
code and log text as non-authoritative.

The active CoPaw Heartbeat implementation hashes are:

| File | SHA-256 |
|---|---|
| `copaw/app/routers/schemas_config.py` | `c655e93c183c0267e918f880f92b459ee294eaae509f2f894fa96cbd439d6057` |
| `copaw/app/routers/config.py` | `ca4ba128ab42813ead1da08beffc4c113b505386fb30d2e8e36eea374234e625` |
| `copaw/app/crons/manager.py` | `7ba6ed4d6117b98a0289f092616f98c63e908da90a97a912883974d64223945f` |

The PUT endpoint saves the complete agent configuration and schedules
`reschedule_heartbeat()` asynchronously. The scheduler removes the existing
`_heartbeat` job, adds it back only when enabled, and emits
`heartbeat disabled, job removed` on the disabled path. Because the HTTP PUT
returns before asynchronous rescheduling completes, R2-3 must require both a
GET readback and a new scheduler log line; the PUT response alone is not
acceptance evidence.

The preserved current Heartbeat JSON is:

```json
{"enabled":true,"every":"30m","target":"main","activeHours":null}
```

Its compact UTF-8 JSON SHA-256 is:

`133b595951f10d4d0f418bcfda39532b0bcab3b022578544397c2ca0ed69ecae`

## MinIO policy and identity evidence

The existing policy inventory contains no
`codesentinel-manager-diff-deployer-v1` policy. Its reviewed, not-yet-created
three-statement template has canonical SHA-256:

`a4ba569aea81bb06c1ea38c58d1cde6c25467513bf86a250ea27153ccbf6362f`

Existing protected policy hashes are:

| Policy | Canonical SHA-256 |
|---|---|
| `worker-default` | `088b591e6985e5601591835bdca8ca1881a4297c560c1fb480d99be53259a22b` |
| `worker-cs-diff-analyzer` | `e18406d5165664fec9dfa80badf6f07884d629f2635bdd6380b7b15e6372f54d` |
| `worker-cs-security-scanner` | `1e666b833ab5f1653a635ff53c56941416ed4266a94ef79ba64660b16ec05e80` |
| `worker-cs-quality-reviewer` | `8b559481001a3adb5dad534c0060396f0057b36f488de6f65de7df07db0e8312` |

Each Worker policy is associated with exactly one user and no group. The
Manager storage identity was matched to the unique `worker-default` subject
without printing it. Its one-way fingerprint is:

`37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f`

The Manager's current identity receives `AccessDenied` for the exact Diff
Skill prefix. Controller administration independently sees that prefix as
empty. This reproduces the original infrastructure blocker without mutation
and proves that R2-4 must add, verify, and later detach only the reviewed
Diff-specific policy.

## Skill, registry, task, route, and usage state

- Diff, Security, and Quality registry `skills` values are all null;
- the active finite-task list is empty;
- all three local Worker CodeSentinel Skill paths are absent;
- all three exact remote CodeSentinel Skill prefixes contain zero objects;
- all four roles use `hiclaw-gateway/deepseek-v4-pro`;
- Diff, Security, and Quality historical DeepSeek call counts remain one each;
- all three Workers have zero DeepSeek calls on 2026-08-02;
- the Manager's 2026-08-02 count was 43 at both the first and final usage
  snapshots, so the observed R2-2 delta was zero;
- the Manager historical DeepSeek total is 110; R2 does not reinterpret this
  background history as CodeSentinel domain-analysis usage.

The final registry semantic SHA-256, excluding only `updated_at` and
per-Worker `skills_updated_at`, is:

`994cd827cf265782b449661ae81a56c6f339be47eeef2e55cdfbca4d7615f05e`

AgentTeams refreshed the managed registry timestamp from
`2026-08-02T10:22:22Z` to `2026-08-02T10:27:10Z` during the inspection window.
The Worker set, room fingerprints, runtimes, and null Skill assignments did not
change. This is recorded as background metadata activity, not a CodeSentinel
mutation.

## Known exact rollback targets for later gates

R2-2 identified every later mutable target before authorization:

- original Heartbeat JSON and hash above;
- proposed policy name and canonical hash above;
- one existing Manager subject, recorded only by its fingerprint;
- current `worker-default` policy and canonical hash, which must remain
  attached and unchanged;
- exact Diff Skill prefix
  `agents/cs-diff-analyzer/skills/codesentinel-diff-review/`;
- exact disposable probe subprefix
  `.codesentinel-r2-probe/` beneath that Skill;
- exact Diff Worker-local Skill path and null registry preimage;
- absent pre-existing proposed policy, probe object, remote Skill, local Skill,
  and registry assignment.

No Security, Quality, shared task, Matrix, route, credential, container, or
volume target is part of a future rollback.

## Non-blocking inspection issues

Three read-only inspection commands required correction:

1. a container `sh` command used unsupported `source`; Controller-side listing
   independently verified the storage prefix and object absence;
2. one scheduler source search was mis-scoped by shell quoting and produced
   excessive irrelevant output; it was discarded and replaced with a fixed
   path, no-pipeline search;
3. the host PowerShell runtime lacked the static `.NET HashData` method; the
   same Heartbeat JSON was successfully hashed with
   `SHA256.Create().ComputeHash()`.

None of these commands wrote a file, called a model, or changed external
state.

## Gate decision

R2-2 acceptance is satisfied: the accepted baseline is pushed, live topology
is known, Dify is stopped, vendor and Heartbeat implementations are pinned,
policy/identity/rollback targets are known without credential disclosure,
Skills are absent, tasks are zero, routes are frozen, and observed usage did
not change.

The next action is **not automatic**. R2-3 temporarily changes Heartbeat state
and requires separate user approval. No MinIO policy action may begin until
R2-3 proves the scheduler removal and a 130-second stable Manager usage window
with unconditional restoration already armed.
