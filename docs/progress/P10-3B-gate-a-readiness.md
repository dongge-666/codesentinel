# P10-3B Gate A readiness evidence

Date: 2026-08-02

Result: **PASS for P10-3B-0 and P10-3B-1; live deployment remains NOT STARTED**

Source baseline: `688d26124fbf9a99a825ed7a9f033aba49ac40b9`

This report records the approved read-only preflight, reproducible build, and
isolated Manager-side staging. It is not evidence that a Worker Skill was
installed, a finite task was registered, or a model was called.

## Scope completed

- verified local `HEAD == origin/main` at the accepted P10-3B plan commit;
- verified the runtime bundle's scoped Git inputs were clean;
- rechecked Docker, AgentTeams, Dify, Worker rooms, model routes, task state,
  registry state, official scripts, and model-call counters;
- built the runtime bundle twice and required byte-identical results;
- materialized three role-isolated Skill deployment packages outside the
  repository source templates;
- validated every runtime binding locally and again in the Manager's isolated
  staging directory;
- compared all staged files between host and Manager by SHA-256;
- ran the complete offline repository quality gate and secret triage;
- rechecked that no Worker, model-call counter, route, or active task changed.

## Infrastructure preflight

| Check | Result |
|---|---|
| Docker client/server | `29.2.1` / `29.2.1` |
| AgentTeams containers | Controller, Manager, Diff, Security, Quality all `Up` on `v1.1.2` images |
| Dify | All Dify runtime containers remain stopped |
| Worker registry | Exactly Diff, Security, and Quality Workers; no CodeSentinel Skill assigned |
| Active finite tasks | None |
| Manager and Worker model configuration | `hiclaw-gateway/deepseek-v4-pro` for all four roles |
| Worker rooms | Three non-empty, distinct room IDs |
| Manager model-call delta | `0` |
| Aggregate Worker model-call delta | `0` |

The official scripts were present and hashed before staging:

- `manage-state.sh`:
  `a0ce3e8edb6e03e9432efd38ecfa31048df54a8a9dd05c0ec56aa00fdd6dd300`;
- `push-worker-skills.sh`:
  `71005e21a23da0914e89c4fdeea66bb8b87270a2d492e13ee367867d03c5875c`.

Observed script behavior confirms `add-finite`, `complete`, exact
`--add-skill`/`--remove-skill`, and `--no-notify` support. Removal remains an
exact-path destructive operation and is not authorized by Gate A.

## Reproducible runtime

Two independent builds produced identical archives and external manifests:

| Field | Value |
|---|---|
| Archive | `codesentinel-agentteams-runtime-0.1.0.pyz` |
| Size | `21961` bytes |
| SHA-256 | `9b1e6779de02f31d2817e389e2e6928a7fde9c60a7494c727875954953f504ab` |
| External-manifest SHA-256 | `8ff3404f20a683a14fff86112cc4e4d19777ffcb0e09388ddcd5597cb355a2b0` |
| Source revision | `688d26124fbf9a99a825ed7a9f033aba49ac40b9` |
| Source dirty | `false` |
| Python/Pydantic contract | `>=3.11,<3.12` / `>=2.13,<3` |

The archive contained exactly 14 allow-listed files and no Provider, scanner,
`.env`, credential, model client, or absolute host path. Local and Manager
self-checks reported Python `3.11.15`, Pydantic `2.13.4`, contract `1.0.0`, and
`model_calls=0`.

## Isolated Skill packages

The host staging root and Manager staging root each contained exactly 29 files.
Using sorted POSIX relative paths and per-file SHA-256 values, both produced the
same tree digest:

`2bfe21b34ac74ca1772e9003ebc615a8f50c9028a0f0d2d2e08d59ec409315d1`

Manager staging root:

`/root/manager-workspace/codesentinel-staging/p10-3b/688d26124fbf9a99a825ed7a9f033aba49ac40b9`

| Skill | Files | Tree SHA-256 |
|---|---:|---|
| `codesentinel-diff-review` | 9 | `0ae14c4e53f399dc217b1bd98e3e529f408970288f4e3b1820baddddd932664a` |
| `codesentinel-security-review` | 9 | `d5914847fb87abec2a04fe29c9aae4e92f1cc2c60ef936c4393b63a19f6bed4a` |
| `codesentinel-quality-review` | 9 | `ac1133f8b583fb9924fae7204993a8f89ce1e42fc17b3ee067501126981c7ecb` |

Each package had its exact nine-file allow-list, a fully materialized
`deployment-manifest.json`, no unresolved deployment placeholder, and a valid
binding to the clean runtime. All six binding checks, three local and three in
Manager staging, passed.

No matching CodeSentinel Skill path existed in any Worker after staging.
Nothing was copied to a Worker or MinIO.

## Offline verification

| Check | Result |
|---|---|
| Complete pytest suite | 259 collected; all passed |
| Ruff over `src` and `tests` | PASS |
| `pip check` | No broken requirements |
| Python compile check | PASS |
| `git diff --check` | PASS |
| Runtime allow-list and self-check | PASS |
| Three local runtime-binding checks | PASS |
| Three Manager runtime-binding checks | PASS |
| Package allow-list and host-path scan | PASS |
| Host-to-Manager per-file and tree hashes | Exact match |

`detect-secrets` reported 21 high-entropy candidates. Structured triage showed
that all 21 were expected immutable hash fields: runtime source-file hashes,
the archive hash, the Git source revision, and the three deployment runtime
hashes/source revisions. No candidate was a credential or model key.

## Observed constraints and strict disposition

### MinIO directory listing

The Manager storage identity returned `Access Denied` for directory-level
`mc ls`. Exact target probing also reported that the pre-deployment Diff Skill
object did not exist, while the local registry and all Worker-visible paths
confirmed no CodeSentinel Skill was installed.

This does not invalidate Gate A because Gate A performs no remote mutation.
For the first live canary, deployment must use exact object paths and verify
the uploaded package by exact pull/hash. If exact post-upload verification is
not possible, Gate B must stop before task registration.

### Background registry timestamp refresh

During the preflight, AgentTeams refreshed only registry `updated_at` and
per-Worker `skills_updated_at` timestamps. The Worker set, room IDs, runtimes,
and `skills=None` state remained unchanged. Manager/Worker model configs and
all four token-usage files retained their original hashes. This is recorded as
background metadata activity, not a CodeSentinel deployment or model call.

### Cross-platform tree hashing

An initial aggregate tree comparison differed because native Windows and Linux
path ordering sorted `SKILL.md` differently. Per-file hashes were already
identical. Recomputing both sides with the same POSIX relative-path ordering
produced the matching tree digest recorded above. No file was repaired or
re-copied.

## Preserved boundaries

- No Skill was copied to MinIO or a Worker.
- No finite task, Matrix event, or taskflow acknowledgement was created.
- No DeepSeek, Manager, or Worker model call was made.
- No gateway, API key, model route, container, volume, restart policy, or Dify
  state changed.
- No repository source template was materialized in place.
- The health-audit report remained excluded from Git.

## Gate decision and next action

Gate A is accepted. Gate B remains **NO-GO** until separately approved.

Because this evidence report changes the documentation commit after the staged
packages were bound to `688d261`, a later Gate B preflight must first rebuild
and re-materialize from the newly accepted clean report commit. That refresh is
zero-model and must again require byte-identical bundles, `source_dirty=false`,
matching host/Manager hashes, and unchanged call-count baselines.

After the report is reviewed, the next safe action is a documentation-only
commit and push. Only then should the user separately approve the refreshed
Diff Worker canary gate.
