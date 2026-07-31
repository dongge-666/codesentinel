# CodeSentinel

CodeSentinel is a planned evidence-driven, multi-agent review gate for local
Git diffs. It is being developed for the GOAI Agent Infra track with
AgentTeams as the collaboration runtime.

## Current status

P1 repository/security baseline, P2 DeepSeek API preflight, P3 AgentTeams
gateway/four-runtime smoke testing, and P4 deterministic contract/policy
kernel are complete. The Manager and three Workers use `deepseek-v4-pro`
through a dedicated authenticated Higress route. Independently, the P4
Policy Engine now produces offline, deterministic gate decisions from strict
immutable contracts.

Git Diff ingestion, real review skills, LLM review behavior, and real
Manager-to-Worker business collaboration are not implemented yet. In
particular, P3 infrastructure smoke testing must not be presented as the P10
multi-agent workflow, and P4 unit evidence must not be presented as an
end-to-end review.

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
