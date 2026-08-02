# R2-3 bounded Manager quiescence window

Date: 2026-08-02

Result: **PASS; GO only for separate R2-4 approval**

Accepted revision: `7f8b3a1589c00ba4fde182b13ed703692804f2bb`

R2 overall status: **in progress; no MinIO policy or Worker Skill mutation has
been authorized or performed**

## Approved boundary

R2-3 temporarily changed only the Manager Heartbeat configuration through the
official CoPaw API. It did not create or attach a MinIO policy, write an object,
deploy or synchronize a Worker Skill, create a finite task, send a Matrix
event, invoke a model, restart a container, or change a route.

An independent hidden PowerShell process owned the complete disable, sampling,
and restore transaction. Its `finally` path retried restoration and required
both exact API readback and a new scheduler reschedule log. This allowed the
original Heartbeat state to be recovered even if the interactive inspection
was interrupted.

## Original configuration and restoration target

The original compact Heartbeat JSON was:

```json
{"enabled":true,"every":"30m","target":"main","activeHours":null}
```

Its SHA-256 was:

`133b595951f10d4d0f418bcfda39532b0bcab3b022578544397c2ca0ed69ecae`

The independent final GET returned the same semantic JSON. The restored
canonical SHA-256 exactly matched the original value, and the Manager emitted
a new `heartbeat rescheduled: every=30m` scheduler log entry.

## Fail-closed harness correction

The first transaction stopped before quiet-window sampling. PowerShell 5
treated the normal stderr stream used by `docker logs` as a terminating native
command error even though Docker exited zero and the expected scheduler text
was present. The guard immediately ran its `finally` path:

- duration: `0.863` seconds;
- disable API readback: `enabled=false`;
- restored API readback: `enabled=true`;
- restored canonical hash: exact original hash;
- model-usage samples: none;
- MinIO, Skill, task, Matrix, route, and container mutations: none.

This was an evidence-harness interpretation error, not a CoPaw failure. The
ignored local helper was corrected to capture Docker's stderr as data and to
match timestamped log objects without weakening the exit-code check. The first
result has local SHA-256:

`464f1e71fd7d7c4984a9455774d8d308a55dccb1daff3d609e0e7cd7eb2ef8f8`

## Accepted quiet-window evidence

The corrected transaction ran from `2026-08-02T11:05:04.1115804Z` through
`2026-08-02T11:07:15.5163094Z`, a total of `131.405` seconds and well within
the frozen 20-minute limit.

Acceptance evidence:

- disabled API readback was `enabled=false`;
- a new `heartbeat disabled, job removed` scheduler log was observed;
- Manager DeepSeek call count at elapsed 0 seconds: `45`;
- Manager DeepSeek call count at elapsed 65 seconds: `45`;
- Manager DeepSeek call count at elapsed 130 seconds: `45`;
- Manager call-count delta during the accepted window: `0`;
- restored API readback was `enabled=true`;
- restored Heartbeat hash matched the original hash;
- a new `heartbeat rescheduled: every=30m` scheduler log was observed;
- operation and restoration error fields were both null.

The accepted local result JSON has SHA-256:

`8f74bd2f17cdcbd57901cadb949cbcfe7d64d97b9c17bc881d21b5e7f85a421b`

The helper used for the transaction has local SHA-256:

`89499484860860b201a1065267fe0bc1645f3457989c73cf64b30f564a38a1ee`

Both artifacts remain ignored under `artifacts/`; this report is the tracked
redacted evidence record.

## Independent post-window verification

After the guard process exited, a separate inspection confirmed:

- Heartbeat remained restored to the complete original configuration;
- Manager DeepSeek call count remained `45`;
- Diff, Security, and Quality historical DeepSeek counts remained `1` each;
- the Manager task-management state reported `No active tasks`;
- all five expected AgentTeams containers remained running;
- no R2 command addressed MinIO, Worker Skill paths, Matrix, or model APIs.

The Manager count had increased from the older R2-2 snapshot of `43` to the
R2-3 pre-window baseline of `45` before R2-3 began. R2-3 does not attribute or
hide that prior background activity. Its accepted claim is the measured zero
delta after scheduler removal, not a zero delta across unrelated time.

## Gate decision

R2-3 acceptance is satisfied. The official Heartbeat API produced verified
hot removal, the 130-second Manager usage interval was stable, and the exact
original scheduler state was restored and independently re-read.

The next action is **not automatic**. R2-4 creates and temporarily attaches the
reviewed Diff-prefix MinIO policy and performs positive and negative capability
probes. That persistent external mutation requires separate user approval.
