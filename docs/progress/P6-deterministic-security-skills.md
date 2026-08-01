# P6 deterministic security Skills

Status: completed
Date: 2026-07-31

## Outcome

P6 adds three local, deterministic, versioned security Skills over the P5
`GitDiffArtifact` boundary:

| Skill | Deterministic coverage | Independent adapter |
|---|---|---|
| `detect_secret@1.0.0` | exact OpenAI-style, AWS, and GitHub token rules | detect-secrets 1.5.x |
| `detect_injection@1.0.0` | dynamic SQL construction and shell-command composition | Python AST/rules |
| `detect_dangerous_call@1.0.0` | eval/exec, `os.system`, and shell-enabled subprocess | Bandit 1.9.x |

Each Skill publishes its purpose, owner, stage, input/output schema, trigger,
dependencies, permission boundary, deterministic marker, timeout/retry policy,
failure behavior, safety statement, reuse boundary, and rollback version.
Their outputs use the P4 `Finding`, `Evidence`, and `CoverageRecord` contracts.

P6 performs no DeepSeek or AgentTeams call. It does not execute, import, or
modify reviewed code.

## Evidence and finding boundary

- exact built-in rules create confirmed high-severity findings with
  reproducible E3 rule evidence;
- tool-only detect-secrets or Bandit observations create suspected E2 evidence
  and cannot independently satisfy an E3 blocking rule;
- findings are created only for added Python lines, except secret detection,
  which checks every text diff line so masking can happen before disclosure;
- a secret found only on the deleted side creates no Finding or verified E3
  entry, so deletion does not introduce a blocking finding;
- locations preserve repository-relative path, hunk ID, side, new line number,
  and source hash;
- stable IDs include the diff hash, Skill/rule version, location, and content
  identity, making reruns reproducible and multiple secrets on one line distinct.

The P4 policy still owns the actual `PASS`, `BLOCK`, and `NEEDS_REVIEW`
decision. P6 only supplies qualified observations and a trusted E3 registry;
workflow-level policy integration remains scheduled for P8-P10.

## Secret handling and cloud boundary

All secret scanning occurs locally. Plaintext values exist only while matching
the already-local P5 line and are not fields in any public result contract.
P6 emits:

- a one-way SHA-256 secret fingerprint;
- a stable redaction ID;
- masked content such as `<REDACTED:TYPE:fingerprint-prefix>`;
- a `SanitizedDiffView` that contains only supported Python diff lines.

The view is `cloud_safe=true` only after the mandatory secret Skill succeeds
and the P5 changed-line limit is satisfied. If secret scanning fails, its lines
are empty and `cloud_safe=false`. This prevents later P7 code from sending an
unverified source payload to a model.

## Tool isolation and failure behavior

detect-secrets scans source lines in memory. Bandit receives only individually
AST-parseable added statements in a short-lived synthetic Python file, invoked
with an argument list and no shell. The temporary file is owner-only where the
operating system supports it and is removed when the adapter exits.

Timeouts, invalid tool output, process failures, and unexpected adapter
exceptions do not produce a clean result. The affected Skill returns:

- `status=failed`;
- `coverage.status=failed`;
- a safe standard error code;
- E0 system evidence;
- no findings and no verified E3 IDs.

If the failed Skill is secret detection, the aggregate scan also denies all
source disclosure.

## Verification

P6 adds 19 tests using real temporary Git repositories and P5 parsing. They
cover:

- dynamically generated synthetic credentials, plaintext absence, masking,
  fingerprints, and deleted-secret behavior;
- SQL concatenation, SQL f-strings, dynamic `os.system`, and shell-enabled
  subprocess calls with exact new-side locations;
- a safe subprocess argument list with no high-risk finding;
- eval, exec, `os.system`, and shell-enabled subprocess dangerous-call rules;
- deleted dangerous calls remaining outside finding scope;
- typed and unexpected adapter failures producing E0 and failed coverage;
- fixed Skill order, aggregate evidence, verified E3 registration, schema
  metadata, deterministic IDs, and fail-closed sanitized views;
- real detect-secrets and Bandit execution.

Acceptance results:

```text
P6 Skill tests: 19 passed
Full P1-P6 tests: 174 passed
Ruff: all checks passed
pip check: no broken requirements found
repository credential-pattern scan: no matches
git diff --check: passed
```

## Resolved implementation issue

The real-adapter test showed that multiple detect-secrets plugins can report
different observations on one line. A location-only identity would collide.
Finding and evidence identity now includes a one-way value fingerprint, while
the serialized report still excludes plaintext. This preserves deterministic
deduplication without collapsing distinct secrets.

## Deliberate P6 limitations

- deterministic AST rules accept complete single-line Python statements;
- this is an MVP rule set, not a complete SAST replacement;
- no LLM semantic review, structured model adapter, prompt, or model retry;
- no risk router, conflict resolver, directed recheck, CLI, report, or
  AgentTeams business workflow;
- the sanitized diff is a contract boundary for P7, not proof that any cloud
  request has occurred.

These limitations belong to P7-P10 and must not be presented as implemented in
the preliminary submission.
