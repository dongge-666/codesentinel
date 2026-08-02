# R1 security detection correctness remediation

Status: implemented, locally validated, and approved for an independent commit
Date: 2026-08-02
Baseline: `4ffc1c82a7f870029594fc2f2bc4705c6f1ac9b5`

## Why R1 was required

The P1-P10 health audit reproduced two decision-changing defects in the P6
deterministic security boundary:

1. multiline `subprocess.run(..., shell=True)` and `eval(...)` calls could be
   skipped by isolated-line AST parsing while Coverage still reported
   `completed`, allowing the reference gate to return `PASS`;
2. dynamic explanatory text containing a SQL keyword could be classified as
   confirmed SQL injection without reaching a database execution sink,
   causing an incorrect `BLOCK`.

R1 froze both behaviors as Skill-level and end-to-end gate regressions before
changing the implementation.

## Implemented corrections

- added bounded, new-side hunk reconstruction with AST node-to-Git-line
  mapping;
- added a safe wrapper strategy for indented partial hunks;
- made unparseable Python context fail with
  `CONTEXT_INSUFFICIENT` and failed Coverage instead of silently claiming
  completion;
- resolved explicit aliases for `subprocess`, `os`, and built-in dangerous
  calls;
- limited confirmed SQL injection to dynamic SQL reaching `execute`,
  `executemany`, or `executescript`, including local assignment tracing;
- limited injection and dangerous-call `files_checked` to Python files whose
  added lines were actually inspected;
- bound every sanitized line to both its source-content hash and its current
  content hash;
- bound exposed line locations and order to the original `GitDiffArtifact`;
- allowed only verifiable redaction-only transformations before P7 context
  construction;
- added content-hash validation to final `AgentContextLine` objects;
- versioned the corrected detectors, `SanitizedDiffView`, and aggregate scan
  as `1.1.0`; the frozen MVP policy explicitly qualifies both `1.0.0` and
  `1.1.0` detector evidence.

Historical serialized `SanitizedDiffView@1.0.0` artifacts must be rebuilt from
their original Git comparison before replay. They are intentionally not
silently upgraded because they lack the new source-line lineage fields.

## Regression guarantees

The R1 tests require all of the following:

- multiline shell execution and multiline `eval` produce confirmed E3
  findings at real added line numbers;
- the same dangerous change cannot produce a final `PASS`;
- benign dynamic text containing `SELECT` can produce a final `PASS` when no
  other risk exists;
- direct and assignment-mediated dynamic SQL is detected only when it reaches
  a database sink;
- parameterized SQL remains free of a confirmed SQL-injection finding;
- aliases, comments, strings, deleted calls, and indented partial hunks follow
  deterministic behavior;
- AST reconstruction failure produces failed Coverage;
- recomputed foreign hashes, altered locations, and content injected after a
  redaction are rejected before a cloud model context can be built.

## Validation and residual items

Final local validation for this uncommitted slice produced:

- 259 collected tests, all passing;
- 82% repository-wide branch coverage;
- 84% coverage for `detect_injection`, 88% for shared hunk AST reconstruction,
  and 91% for `detect_dangerous_call`;
- Ruff lint, dependency integrity, compile checks, and `git diff --check`
  passing;
- Bandit reporting 10 Low, 1 previously documented Medium B310 in the Matrix
  probe, and no High findings;
- detect-secrets reporting 13 triaged keyword/fixed-hash/test-fixture
  candidates and no newly exposed live credential;
- an offline `codesentinel-0.1.0` wheel build, clean target install, corrected
  detector/version imports, and policy load passing.

The repository-wide Ruff formatting debt and the existing Bandit B310 finding
in the constrained Matrix probe remain separately tracked S3/S2 hardening
items. R1 does not deploy Worker Skills, call DeepSeek, change Docker, or alter
Git history.
