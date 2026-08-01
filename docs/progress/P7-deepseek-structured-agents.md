# P7 DeepSeek Provider and structured Agents

Status: completed
Date: 2026-08-01

## Outcome

P7 converts the P2 connectivity proof and P6 cloud-safe diff into a reusable
model boundary plus three strict analysis roles:

| Agent | Input boundary | Successful domain output | Prompt version |
|---|---|---|---|
| Diff Analyzer | sanitized lines and file metadata | `DiffAnalysis@1.0.0` | `diff-analyzer-1.0.0` |
| Security Scanner | sanitized lines, deterministic security summaries, coverage | `SecurityReview@1.0.0` | `security-semantic-1.0.0` |
| Quality Reviewer | sanitized lines and Ruff summary | `QualityReview@1.0.0` | `quality-review-1.0.0` |

Security and Quality outputs are frozen P4 `AgentArtifact` values. P7 does not
run a gate policy, build a RiskMap, perform a directed recheck, expose a CLI,
or dispatch AgentTeams tasks.

## Provider contract

`DeepSeekProvider` uses the OpenAI-compatible Chat Completions API with the
frozen `deepseek-v4-pro` model. Current request behavior follows the official
[Chat Completion contract](https://api-docs.deepseek.com/api/create-chat-completion)
and [JSON Output guidance](https://api-docs.deepseek.com/guides/json_mode/):

- JSON mode plus an explicit target JSON Schema in every request;
- local Pydantic validation remains authoritative;
- temperature is fixed at `0.1`;
- Diff analysis uses non-thinking mode;
- Security and Quality use thinking mode with `high` reasoning effort;
- output is capped per role and streaming is disabled;
- the SDK's automatic retry is disabled so CodeSentinel owns retry accounting;
- transient network, timeout, 429, and 5xx failures receive at most one retry;
- empty, truncated, invalid-JSON, or schema-invalid output receives at most one
  regeneration from the original sanitized context;
- one thread-safe `ModelCallBudget` caps an entire review at four requests.

Normal Diff, Security, and Quality execution consumes three calls, leaving one
slot for a bounded schema repair or future P8-directed use. Exhaustion returns
`BUDGET_EXCEEDED` and no model output.

## Context isolation and privacy

Context builders accept only a P6 `SanitizedDiffView` whose `review_id` and
source diff hash match the P5 artifact and whose `cloud_safe` flag is true.
Secret-scan failure blocks construction before a Provider call.

| Context | Included | Excluded |
|---|---|---|
| Diff | sanitized diff lines, file/totals metadata | Security/Quality conclusions |
| Security | sanitized lines, deterministic Finding summaries and coverage | gate outcome, Quality context |
| Quality | sanitized lines and a bounded Ruff summary | Security findings and free reasoning |

Cloud payloads omit local review and artifact IDs. Paths and source are limited
to the approved diff. Prompts label code as untrusted data and instruct the
model to ignore embedded instructions; strict local schemas prevent repository
text from adding gate decisions, evidence levels, or out-of-role fields. This
reduces but does not claim to eliminate model-level prompt-injection risk.

The Provider reads only final `message.content`. It never reads or serializes
`reasoning_content`. `ModelCallRecord` contains request/response hashes,
version, global review call index, attempt purpose, latency, token usage, and
estimated cost; it has no prompt, source, response, Authorization header, or
reasoning field.

## Evidence trust boundary

The model schema has no evidence-level or gate-decision field. Security and
Quality drafts are converted locally to:

- `Finding.status=suspected`;
- `Evidence.source=llm`;
- `Evidence.level=E1`;
- locations resolved only from supplied opaque `line_ref` values.

Unknown line references fail domain conversion. Extra fields such as a model
claiming `evidence_level=E3` fail schema validation and can only trigger the
single bounded regeneration. Therefore P7 cannot self-register trusted E3 or
directly produce `PASS`, `BLOCK`, or `NEEDS_REVIEW`.

## Usage and cost telemetry

P7 records prompt, cache-hit, cache-miss, completion, and total tokens where
the Provider returns them. Cost is estimated from the official
[DeepSeek pricing table](https://api-docs.deepseek.com/quick_start/pricing/)
snapshot dated 2026-08-01:

- V4 Pro cache-hit input: USD 0.003625 per million tokens;
- V4 Pro cache-miss input: USD 0.435 per million tokens;
- V4 Pro output: USD 0.87 per million tokens.

Pricing is versioned metadata, not a permanent claim. If cache detail is absent,
all prompt tokens are conservatively priced as cache misses.

## Verification

P7 adds 20 offline tests. They cover:

- all three target schemas and prompt versions;
- role-isolated payload contents and review-ID omission;
- P6-to-P7 indentation preservation and pre-cloud secret masking;
- secret-scan failure preventing context creation;
- E1-only LLM evidence and rejection of self-declared E3;
- line-reference containment;
- invalid JSON, empty output, schema errors, one regeneration, timeouts, 429,
  bounded `Retry-After`, repeated failures, and budget exhaustion;
- global review call numbering, token/cost accounting, API-key redaction, and
  reasoning-content disposal;
- a fully mocked live-report harness with no network dependency.

Offline acceptance results:

```text
P7 tests: 20 passed
Full P1-P7 tests: 194 passed
Ruff: all checks passed
pip check: no broken requirements found
repository credential-pattern scan: no matches
git diff --check: passed
```

## Live API verification

The ignored `codesentinel-p7-live` probe used one small synthetic Python diff.
It passed on the first attempt against `deepseek-v4-pro`:

| Agent | Calls | Tokens | Estimated USD | Schema |
|---|---:|---:|---:|---|
| Diff Analyzer | 1 | 848 | 0.000394545 | `DiffAnalysis@1.0.0` |
| Security Scanner | 1 | 1305 | 0.000731670 | `SecurityReview@1.0.0` |
| Quality Reviewer | 1 | 1391 | 0.000840420 | `QualityReview@1.0.0` |
| Total | 3/4 | 3544 | 0.001966635 | all valid |

No retry or schema regeneration was needed. The persisted report contains only
the table's metadata, timestamps, model/origin, pricing version, status, and
failure code fields. It excludes the API key, prompts, synthetic code, model
responses, and reasoning content.

## Deliberate P7 limitations

- P7 supplies components, not the P9 single-process review loop;
- role isolation is enforced in local runner contexts, not yet demonstrated
  through AgentTeams collaboration rooms;
- the Quality Agent accepts a Ruff summary but P7 does not schedule Ruff;
- P7 does not perform RiskMap routing, deduplication across Agents, evidence
  conflicts, or directed recheck;
- the live check uses synthetic code and is not an accuracy benchmark;
- estimated prices can change and must be refreshed before final materials.

These limitations belong to P8-P10 and must not be presented as completed
multi-Agent business collaboration in the preliminary submission.
