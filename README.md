# CodeSentinel

CodeSentinel is a planned evidence-driven, multi-agent review gate for local
Git diffs. It is being developed for the GOAI Agent Infra track with
AgentTeams as the collaboration runtime.

## Current status

P1 repository/security baseline, P2 DeepSeek API preflight, P3 AgentTeams
gateway/four-runtime smoke testing, P4 deterministic contract/policy kernel,
P5 read-only Git Diff ingestion, P6 deterministic security Skills, P7
structured DeepSeek analysis Agents, P8 risk/evidence assurance, and the P9
single-process reference CLI are complete. The Manager and three
Workers use `deepseek-v4-pro` through a dedicated authenticated Higress route.
Independently, the domain path now produces strict policy decisions, complete
hashed Git input artifacts, reproducible E3 evidence, a fail-closed sanitized
diff boundary, schema-validated Diff, Security, and Quality model outputs,
deterministic risk routing, evidence conflict detection, a single bounded
targeted recheck, and an auditable end-to-end local reference run.

P10 now has one real, bounded AgentTeams Diff Worker canary with official task
acknowledgement/submission and an independently validated authoritative
delivery. This is not yet the full multi-agent workflow: Security, Quality,
Manager orchestration, and the final gate remain unimplemented. Neither the P3
infrastructure smoke test nor the P9 single-process trace should be presented
as that remaining P10 workflow.

## Frozen MVP boundary

- Python changes in a local Git diff
- Four roles: Gate Arbiter, Diff Analyzer, Security Scanner, Quality Reviewer
- `PASS`, `BLOCK`, and `NEEDS_REVIEW` outcomes
- Read-only access to the reviewed repository
- DeepSeek `deepseek-v4-pro` through an AgentTeams gateway

## Development environment

- Python 3.11
- Git
- Docker Desktop
- AgentTeams v1.1.2

Activate the existing `agent_dev` Conda environment before running project
commands. New capabilities are added only in their approved plan stages.

## Security

Never commit a real API key. `.env` and common credential file formats are
ignored. `.env.example` contains names only and must remain secret-free.

## P2 DeepSeek preflight

P2 uses the ignored local `.env` file. Enter the real key locally after
`DEEPSEEK_API_KEY=` and never paste it into chat. Then run:

```powershell
D:\python\Anaconda\envs\agent_dev\python.exe -m codesentinel.preflight.deepseek
```

The command validates plain chat, JSON output, and one tool call. It stores
only redacted metadata under `artifacts/preflight/`. P2 acceptance completed
with all three live probes passing against `deepseek-v4-pro`.

## P3 AgentTeams gateway smoke

P3 added a dedicated DeepSeek Provider and exact-model Route while preserving
the original Ollama Provider/Route for rollback. The upstream DeepSeek key is
stored only in the ignored local `.env` and the gateway controller; Manager
and Worker containers use separate gateway consumer credentials.

The Manager, Diff Analyzer, Security Scanner, and Quality Reviewer all passed
real CoPaw-to-DeepSeek calls. Security and Quality also passed a two-request
concurrency check. Worker host ports are dynamically assigned after container
reconciliation, so discover them with `docker port <container>` instead of
hard-coding port numbers.

See [the P3 completion report](docs/progress/P3-agentteams-deepseek-smoke.md)
for the redacted evidence, limitations, and rollback procedure.

## P4 deterministic contract and policy kernel

P4 defines ten frozen enums, twelve strict public Pydantic contracts, the
integrity-locked `mvp-1.0.0` policy, trusted-E3 qualification, and a pure
in-memory Policy Engine. It performs no Git, network, model, or AgentTeams
operation.

Run the offline regression suite with:

```powershell
D:\python\Anaconda\envs\agent_dev\python.exe -m pytest -q
D:\python\Anaconda\envs\agent_dev\python.exe -m ruff check src tests
```

See [the P4 completion report](docs/progress/P4-contract-policy-kernel.md)
for the trust boundary, adversarial cases, and phase limitations.

## P5 read-only Git Diff input and artifacts

P5 validates an exact local worktree root, resolves revisions to immutable
commit object IDs, and supports committed revision ranges plus staged,
unstaged, and combined worktree comparisons. It parses file changes, hunks,
old/new line numbers, renames, binary files, unsupported languages, and
explicit size limits without silently truncating the patch.

The resulting `GitDiffArtifact` is local-only and always has
`cloud_safe=false`. P6 must detect and mask secrets before any source can be
eligible for a cloud model. Binary files, unsupported languages, and diffs
over the configured changed-line limit are explicitly ineligible.

Artifacts are written atomically below `artifacts/runs/<review_id>/`, never
inside the reviewed repository. Each run contains `git-diff.json`,
`trace.jsonl`, and a hash manifest. P5 is a Python API boundary; the end-user
CLI is intentionally deferred to P9.

See [the P5 completion report](docs/progress/P5-git-diff-artifacts.md) for
the supported modes, security controls, tests, and known limitations.

## P6 deterministic security Skills

P6 adds `detect_secret`, deterministic `detect_injection`, and
`detect_dangerous_call` as strict versioned Skills. Exact local rules produce
reproducible E3 evidence; independent detect-secrets and Bandit observations
remain E2 unless an approved deterministic rule also confirms the issue.
Only added lines can create security findings. Deleted secrets are masked for
privacy but do not create blocking findings.

Every detected secret is replaced locally with a typed fingerprint placeholder
before a `SanitizedDiffView` can become `cloud_safe=true`. A secret-tool failure
or an oversized diff denies source disclosure and records failed coverage plus
E0 evidence instead of pretending that the scan was safe.

See [the P6 completion report](docs/progress/P6-deterministic-security-skills.md)
for the evidence boundary, adapter behavior, tests, and phase limitations.

## P7 DeepSeek Provider and structured Agents

P7 adds one bounded `deepseek-v4-pro` Provider and three role-isolated runners:
Diff Analyzer, Security Scanner semantic review, and Quality Reviewer. Every
request uses a versioned prompt, low temperature, JSON mode, strict local
Pydantic validation, at most one network retry, and at most one schema
regeneration under a shared four-call review budget.

Only a `cloud_safe=true` P6 view can create model context. Call telemetry stores
hashes, latency, tokens, retry purpose, and estimated cost, but never prompts,
source, credentials, model output, or reasoning content. LLM evidence is
created locally as E1 regardless of what the model tries to claim.

Run the synthetic live check with:

```powershell
D:\python\Anaconda\envs\agent_dev\python.exe -m codesentinel.preflight.p7_agents
```

See [the P7 completion report](docs/progress/P7-deepseek-structured-agents.md)
for the isolation matrix, live metadata, failure behavior, and limitations.

## P8 risk routing and evidence assurance

P8 adds a deterministic `RiskMap`, always-on versus routed Skill plans,
explicit skipped-check reasons, complete Coverage reconciliation, normalized
Finding fingerprints, cross-Agent evidence deduplication, and deterministic
conflict detection. Unresolved contradictions, severity mismatches, and
location mismatches are passed to the P4 policy as `NEEDS_REVIEW` evidence
conflicts.

The targeted recheck controller accepts only exact findings, locations,
conflicts, Skills, and routes. It can run once, preserves original evidence,
requires new non-LLM E2/E3 support before confirming or dismissing a Finding,
and always reruns the deterministic Policy Engine. Invalid, timed-out, or still
inconclusive rechecks exhaust automatically under `N008`.

See [the P8 completion report](docs/progress/P8-risk-evidence-recheck.md) for
the trust boundary, acceptance evidence, and phase limitations.

## P9 local reference runner and CLI

P9 connects the P5-P8 domain components into a fail-closed local review. It
persists JSON contracts, a Markdown report, an ordered JSONL trace, model-call
metadata, and a SHA-256 manifest outside the reviewed repository. Stable exit
codes are PASS=0, BLOCK=1, NEEDS_REVIEW=2, and execution failure=3.

Run a tracked local Git diff with:

```powershell
D:\python\Anaconda\envs\agent_dev\Scripts\codesentinel.exe `
  D:\path\to\reviewed-repository `
  --workspace D:\path\to\codesentinel `
  --env-file D:\path\to\codesentinel\.env
```

The workspace must be separate from the reviewed target. P9 is intentionally
a sequential reference runner, not AgentTeams collaboration.

See [the P9 completion report](docs/progress/P9-local-reference-runner-cli.md)
for the CLI contract, artifact bundle, real API evidence, and limitations.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
