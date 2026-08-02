# R2-4 Diff-only policy probe attempt 1

Date: 2026-08-02

Result: **BLOCKED at policy canonical-hash gate; fail-closed rollback complete**

Accepted revision: `7f8b3a1589c00ba4fde182b13ed703692804f2bb`

R2 overall status: **blocked pending review of the policy canonicalization
contract; R2-4 capability probes were not executed**

## Approved boundary

The approved R2-4 scope permitted one exact Diff-only MinIO policy, one exact
Manager attachment, one disposable object below the approved Diff Skill
prefix, positive and negative capability probes, and exact rollback. It did
not permit Skill deployment, finite tasks, Matrix events, model calls,
Security or Quality changes, container restart, or a relaxed policy scope.

An independent hidden PowerShell process owned the complete Heartbeat,
policy, probe, rollback, and restoration transaction. Its `finally` path could
remove only the named policy and nonce-bound objects and restore the complete
original Heartbeat configuration.

## Precondition evidence

Before the transaction:

- local `HEAD` and `origin/main` both equaled the accepted revision;
- `codesentinel-manager-diff-deployer-v1` was absent;
- `worker-default` had exactly one user and no group;
- that user's one-way fingerprint was
  `37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f`;
- the exact Diff Skill prefix contained zero objects;
- the Manager was denied access to that prefix;
- Diff, Security, and Quality registry Skill assignments were null;
- the three protected Worker-local Skill paths were absent;
- active finite-task count was zero;
- Manager current-day DeepSeek count was `45`, and the three Worker historical
  DeepSeek counts were `1` each.

## Quiet-window evidence

The transaction ran from `2026-08-02T11:36:43.5714999Z` through
`2026-08-02T11:38:58.1948005Z`.

- disabled Heartbeat API readback succeeded;
- a new `heartbeat disabled, job removed` scheduler log was observed;
- Manager calls at elapsed 0 seconds: `45`;
- Manager calls at elapsed 65 seconds: `45`;
- Manager calls at elapsed 130 seconds: `45`;
- accepted quiet-window call delta: `0`.

No policy mutation began until the 130-second window had passed.

## Hard-stop finding

The reviewed source policy canonical hash, with object keys sorted and array
order preserved, was:

`a4ba569aea81bb06c1ea38c58d1cde6c25467513bf86a250ea27153ccbf6362f`

MinIO accepted the policy source, but the immediate policy readback canonical
hash was:

`02e7b1ccae93d69563f9a01b45bfd5929aa35fbcf3ac59b67ecec6abe695f148`

That second value equals the reviewed source after recursively sorting only
string arrays while retaining statement order. This is consistent with MinIO
normalizing action/resource/prefix array ordering. It is not accepted as proof
under the frozen R2-4 contract because that contract specified only the first
canonical hash and did not define separate source-exact and server-semantic
normalization rules.

The guard therefore stopped before attachment. No Manager identity received
the new policy, and no positive or negative object capability probe ran.

## Rollback and independent verification

The exact newly created policy was removed before Heartbeat restoration.
Independent post-process inspection confirmed:

- proposed policy absent;
- exact Diff Skill prefix object count `0`;
- original Heartbeat restored as
  `{"enabled":true,"every":"30m","target":"main","activeHours":null}`;
- restored Heartbeat SHA-256 matched
  `133b595951f10d4d0f418bcfda39532b0bcab3b022578544397c2ca0ed69ecae`;
- new `heartbeat rescheduled: every=30m` log observed;
- Manager DeepSeek count still `45`;
- three Worker historical DeepSeek counts still `1` each;
- no active tasks and all three registry Skill assignments still null;
- exactly the five expected AgentTeams containers remained running;
- protected `worker-default` semantic SHA-256 remained
  `088b591e6985e5601591835bdca8ca1881a4297c560c1fb480d99be53259a22b`;
- `worker-default` still had exactly one user, no group, and the same subject
  fingerprint.

The local redacted result JSON has SHA-256:

`aaea21539ea25a9341a83fd679053e3273d43f36aab31c30190ad36c76557a1c`

The ignored transaction helper has SHA-256:

`97a6d9a8a9832b91b0e8b5719f1eb10d5a76dd07ff6031e2fa449772b55e750e`

## Gate decision and required amendment

R2-4 remains **NO-GO**. This attempt must not be represented as a successful
least-privilege capability probe.

Before a retry, the R2 plan must separately define and review both:

1. the immutable source-policy exact hash; and
2. a server-readback semantic hash that sorts only string arrays, preserves
   statement order, and still requires exact effects, actions, resources, and
   conditions.

The amendment must not allow statement removal, new actions, broader resources,
wildcard expansion, extra prefixes, or attachment to another subject. After
that amendment is reviewed, a retry requires fresh user approval. R2-5 and the
P10-3B Canary remain blocked until R2-4 passes.
