# P9 local reference runner and CLI

Status: completed
Date: 2026-08-01

## Outcome

P9 joins the validated P5-P8 components into one user-executable, fail-closed
review loop. The `codesentinel` CLI reads a local tracked Git diff, creates a
secret-safe model context, runs the three structured DeepSeek reviewers,
routes deterministic security Skills, validates evidence, performs at most one
targeted recheck, executes the frozen Policy, and atomically persists a
review bundle.

This is a single-process reference runner. It is not the AgentTeams business
runtime and its local trace must not be represented as multi-Agent
collaboration evidence. Real Manager-to-Worker dispatch remains P10.

## Reference flow

The frozen P9 order is:

1. validate the artifact boundary and read the Git diff without optional
   locks;
2. always run `detect_secret` and create a redacted `SanitizedDiffView`;
3. run Diff Analyzer and build the deterministic-plus-semantic RiskMap;
4. execute only the deterministic Skills selected by that RiskMap;
5. run Security Scanner and Quality Reviewer over isolated sanitized inputs;
6. assemble strict SecurityReview and QualityReview artifacts;
7. validate evidence, Coverage, lineage, fingerprints, and conflicts;
8. attempt one bounded deterministic recheck when policy permits;
9. rerun the immutable `mvp-1.0.0` Policy;
10. atomically persist the complete result outside the reviewed repository.

One `ModelCallBudget` caps a review at four calls. Normal execution uses three
calls. The final gate is always produced by the deterministic Policy Engine,
never by a model.

## CLI contract

After activating `agent_dev`, or by using the explicit executable path, run:

```powershell
D:\python\Anaconda\envs\agent_dev\Scripts\codesentinel.exe `
  D:\path\to\reviewed-repository `
  --workspace D:\path\to\codesentinel `
  --env-file D:\path\to\codesentinel\.env
```

The target must be the exact Git worktree root. Supported comparisons are a
committed `--base/--target` range, staged-only, unstaged-only, or the default
combined tracked worktree diff. P5 does not support untracked files. A target
revision cannot be mixed with a staged/unstaged-only mode.

The workspace must already exist and must not be inside the reviewed target.
An optional `--review-id` must be path-safe and unique. Invalid boundaries and
duplicate IDs are rejected before model calls. The default whole-run soft
deadline is 240 seconds and can be set from 30 to 600 seconds.

Exit codes are stable:

| Result | Exit code | Meaning |
|---|---:|---|
| `PASS` | 0 | Policy permits the reviewed change |
| `BLOCK` | 1 | Deterministic policy found blocking evidence |
| `NEEDS_REVIEW` | 2 | Evidence or execution is insufficient for automation |
| execution failure | 3 | No valid persisted gate result was produced |

Provider authentication, timeout, transport, schema, and budget failures are
recorded as safe codes and cannot become PASS. Git commands have a 30-second
per-command timeout, Bandit has a 10-second timeout, Provider calls have a
45-second timeout, and the runner checks the whole-run deadline between
bounded stages. This is a soft total deadline: the currently active bounded
operation is allowed to return before the next-stage check rejects the run.

## Persisted review bundle

Every successful persistence creates
`artifacts/runs/<review-id>/` in the CodeSentinel workspace with:

- `input-summary.json`: Git metadata and hashes without raw source;
- `sanitized-diff.json`: redacted model-eligible lines;
- `diff-analysis.json` and `risk-routing.json`;
- `security-review.json` and `quality-review.json`;
- `evidence-validation.json` and `gate-decision.json`;
- `model-calls.json`: secret-free call metadata, Tokens, latency, and cost;
- `review.json`: final status, errors, metrics, and explicit reference-runner
  identity;
- `trace.jsonl`: ordered single-process stage events;
- `report.md`: human-readable decision, findings, actions, errors, and metrics;
- `manifest.json`: SHA-256 hashes for every other persisted file.

The directory is built under a temporary name and renamed only after all
files are complete. PASS is printed only after persistence succeeds. Raw Git
patches, credentials, prompts, model output text, and reasoning content are
not stored.

## Verification

The P9 integration suite covers the stable CLI modes and exit codes, complete
artifact hashes, exact trace ordering, target-repository immutability, a safe
PASS, deterministic secret BLOCK, evidence-insufficient NEEDS_REVIEW,
Provider timeout degradation, secret non-persistence, invalid boundary and
review-ID rejection, routed Skill skipping, and the whole-run deadline.

Acceptance evidence after implementation:

```text
P9 runtime tests: 14 passed
Full P1-P9 tests: 219 passed
Ruff: all checks passed
pip check: no broken requirements found
editable CLI installation: passed
installed CLI help smoke: passed
```

A real DeepSeek integration run over a semantic-preserving synthetic Python
refactor produced `PASS/P001`, used 3 of 4 calls, 3,687 Tokens, and an
estimated cost of USD 0.00197272. The reviewed fixture retained exactly its
pre-run worktree modification and received no CodeSentinel files.

An earlier synthetic `value + 1` behavior change without a matching test was
correctly escalated to `NEEDS_REVIEW/N005/N008`. This was not treated as a
safe PASS sample or used to weaken policy; it provides additional fail-closed
evidence.

## Deliberate P9 limitations

- execution is sequential and local; there is no AgentTeams dispatch,
  parallel Worker scheduling, room trace, or Manager arbitration;
- a model-only medium Finding remains manual after the deterministic recheck;
- the stable three-case demonstration belongs to P11 and the 24-case accuracy
  evaluation belongs to P12;
- no accuracy, recall, efficiency improvement, or competition-compliance
  completion claim is made before the later evaluation and AgentTeams stages;
- P9 does not modify, comment on, or merge a reviewed repository.
