# P10-1 contract and runtime-plan freeze

Date: 2026-08-01

Result: **PASS for P10-1**

P10 overall status: **in progress, not yet accepted**

## Scope completed

P10-1 froze the AgentTeams integration boundary before any business-code
implementation:

- existing Manager plus three existing Worker rooms;
- Matrix control-plane and MinIO artifact-plane responsibilities;
- host-only Git and secret-redaction boundary;
- request, Worker delivery, artifact, identifier, and digest contracts;
- dispatch order, real Security/Quality concurrency evidence, and state machine;
- deterministic gate ownership and independent host verification;
- model-call budget, retry budget, timeouts, cancellation, trace, and replay;
- runtime-bundle deployment rule, compatibility gate, and rollback plan.

The frozen normative contract is
[`docs/design/P10-agentteams-contract.md`](../design/P10-agentteams-contract.md).

## P10-0 evidence used

- Docker Desktop and Docker Engine were available.
- AgentTeams Controller, Manager, Diff, Security, and Quality containers were
  running on pinned `v1.1.2` images.
- Manager and all Workers reported the effective model `deepseek-v4-pro`
  through provider `hiclaw-gateway`.
- The three Workers already had independent Matrix rooms; no AgentTeams Team
  existed, so P10 does not add a fifth Team Leader.
- The current CodeSentinel repository was not mounted into the Manager or
  Workers. The contract therefore uses the supported explicit MinIO sync path.
- Worker runtimes had Python 3.11 and Pydantic, but did not have Bandit or
  detect-secrets. The contract keeps the complete P6 deterministic scan at the
  trusted host ingress and forbids ad-hoc installation in live containers.
- AgentTeams roles used gateway consumer credentials rather than the upstream
  DeepSeek key; no credential value was printed or recorded.
- Local and `origin/main` both pointed to P9 commit `3a68b4a`.

## Dify pause evidence

The twelve active Dify runtime containers were stopped by exact container name
with a graceful timeout. No container, volume, configuration, network, or
restart policy was removed or changed.

Post-stop verification reported:

- Dify running containers: `0`;
- all five AgentTeams containers: `Up`;
- AgentTeams images: still pinned to `v1.1.2`.

Dify uses automatic restart policies, so its status must be checked again after
the next Docker Desktop restart.

## Frozen budget

- three normal domain calls: Diff, Security, and Quality;
- one shared reserve domain call for schema repair **or** targeted semantic
  recheck;
- maximum domain calls per review: `4`;
- maximum total AgentTeams model calls per review: `8`;
- deterministic tools and validators do not consume model-call budget.

## Verification

- `git diff --check` found no whitespace error; Windows emitted only the known
  LF-to-CRLF working-copy warning for `docs/README.md`;
- documentation links and required frozen terms were checked locally;
- Docker state was re-read after the Dify pause;
- no DeepSeek or other model call was made;
- no application source, dependency, image, gateway, key, room, or volume was
  changed;
- no commit or push was created.

## Objective assessment

P10-1 is complete and the implementation boundary is sufficiently precise to
start a small compatibility slice. The result is optimistic because the
infrastructure and routing baseline are healthy and rollback remains P9.

Two implementation risks remain deliberately gated:

1. the versioned runtime bundle must load reproducibly inside both Manager and
   Worker CoPaw runtimes without a live install;
2. real structured task exchange must prove that Matrix contains only control
   data while MinIO carries the hashed artifact.

These are P10-2 acceptance items, not reasons to weaken the contract. P10-2
requires separate user approval and must not implement the full workflow in one
step.
